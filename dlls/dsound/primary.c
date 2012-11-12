/*  			DirectSound
 *
 * Copyright 1998 Marcus Meissner
 * Copyright 1998 Rob Riggs
 * Copyright 2000-2002 TransGaming Technologies, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * TODO:
 *      When PrimarySetFormat (via ReopenDevice or PrimaryOpen) fails,
 *       it leaves dsound in unusable (not really open) state.
 */

#include <stdarg.h>

#define COBJMACROS
#define NONAMELESSSTRUCT
#define NONAMELESSUNION
#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "mmsystem.h"
#include "winternl.h"
#include "mmddk.h"
#include "wine/debug.h"
#include "dsound.h"
#include "dsound_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(dsound);

static void DSOUND_ReleaseDevice(DirectSoundDevice *device)
{
    if(device->client){
        IAudioClient_Release(device->client);
        device->client = NULL;
    }
    if(device->render){
        IAudioRenderClient_Release(device->render);
        device->render = NULL;
    }
    if(device->volume){
        IAudioStreamVolume_Release(device->volume);
        device->volume = NULL;
    }

    if (device->pad) {
        device->playpos += device->pad;
        device->playpos %= device->buflen;
        device->pad = 0;
    }
}

static HRESULT DSOUND_PrimaryOpen(DirectSoundDevice *device, WAVEFORMATEX *wfx, DWORD aclen, BOOL forcewave)
{
    IDirectSoundBufferImpl** dsb = device->buffers;
    LPBYTE newbuf;
    DWORD i, new_buflen;
    BOOL mixfloat = FALSE;

    TRACE("(%p)\n", device);

    new_buflen = device->buflen;
    new_buflen -= new_buflen % wfx->nBlockAlign;

    if (wfx->wFormatTag == WAVE_FORMAT_IEEE_FLOAT ||
        (wfx->wFormatTag == WAVE_FORMAT_EXTENSIBLE &&
         IsEqualGUID(&((WAVEFORMATEXTENSIBLE*)wfx)->SubFormat, &KSDATAFORMAT_SUBTYPE_IEEE_FLOAT)))
        mixfloat = TRUE;

    /* reallocate emulated primary buffer */
    if (forcewave) {
        if (device->buffer)
            newbuf = HeapReAlloc(GetProcessHeap(), 0, device->buffer, new_buflen);
        else
            newbuf = HeapAlloc(GetProcessHeap(), 0, new_buflen);

        if (!newbuf) {
            ERR("failed to allocate primary buffer\n");
            return DSERR_OUTOFMEMORY;
        }
        device->mix_buffer_len = 0;
    } else if (!mixfloat) {
        DWORD alloc_len = aclen / (wfx->nBlockAlign / 8) * sizeof(float);

        if (device->buffer)
            newbuf = HeapReAlloc(GetProcessHeap(), 0, device->buffer, alloc_len);
        else
            newbuf = HeapAlloc(GetProcessHeap(), 0, alloc_len);

        if (!newbuf) {
            ERR("failed to allocate primary buffer\n");
            return DSERR_OUTOFMEMORY;
        }
        device->mix_buffer_len = alloc_len;
    } else {
        HeapFree(GetProcessHeap(), 0, device->buffer);
        newbuf = NULL;
        device->mix_buffer_len = 0;
    }

    device->buffer = newbuf;
    device->buflen = new_buflen;
    HeapFree(GetProcessHeap(), 0, device->pwfx);
    device->pwfx = wfx;

    device->writelead = (wfx->nSamplesPerSec / 100) * wfx->nBlockAlign;

    TRACE("buflen: %u, fraglen: %u, mix_buffer_len: %u\n",
          device->buflen, device->fraglen, device->mix_buffer_len);

    if (!forcewave && !mixfloat)
        device->normfunction = normfunctions[wfx->nBlockAlign/8 - 1];
    else
        device->normfunction = NULL;

    if (device->mix_buffer_len)
        FillMemory(device->buffer, device->mix_buffer_len, 0);
    else if (device->buffer)
        FillMemory(device->buffer, device->buflen, (wfx->wBitsPerSample == 8) ? 128 : 0);
    device->playpos = 0;

    for (i = 0; i < device->nrofbuffers; i++) {
        RtlAcquireResourceExclusive(&dsb[i]->lock, TRUE);
        DSOUND_RecalcFormat(dsb[i]);
        RtlReleaseResource(&dsb[i]->lock);
    }

    return DS_OK;
}

static WAVEFORMATEX *DSOUND_WaveFormat(DirectSoundDevice *device, IAudioClient *client, BOOL forcewave)
{
    WAVEFORMATEXTENSIBLE *retwfe = NULL;
    WAVEFORMATEX *w;
    HRESULT hr;

    if (!forcewave) {
        WAVEFORMATEXTENSIBLE *mixwfe;
        hr = IAudioClient_GetMixFormat(client, (WAVEFORMATEX**)&mixwfe);

        if (FAILED(hr))
            return NULL;

        if (mixwfe->Format.nChannels > 2) {
            static int once;
            if (!once++)
                FIXME("Limiting channels to 2 due to lack of multichannel support\n");

            w = &mixwfe->Format;
            w->nChannels = 2;
            w->nBlockAlign = w->nChannels * w->wBitsPerSample / 8;
            w->nAvgBytesPerSec = w->nSamplesPerSec * w->nBlockAlign;
        }

        if (!IsEqualGUID(&mixwfe->SubFormat, &KSDATAFORMAT_SUBTYPE_IEEE_FLOAT)) {
            WAVEFORMATEXTENSIBLE testwfe = *mixwfe;

            testwfe.SubFormat = KSDATAFORMAT_SUBTYPE_IEEE_FLOAT;
            testwfe.Format.wBitsPerSample = 32;
            testwfe.Samples.wValidBitsPerSample = 0;

            if (FAILED(IAudioClient_IsFormatSupported(client, AUDCLNT_SHAREMODE_SHARED, &testwfe.Format, (WAVEFORMATEX**)&retwfe)))
                w = DSOUND_CopyFormat(&mixwfe->Format);
            else if (retwfe)
                w = DSOUND_CopyFormat(&retwfe->Format);
            else
                w = DSOUND_CopyFormat(&testwfe.Format);
            CoTaskMemFree(retwfe);
            retwfe = NULL;
        } else
            w = DSOUND_CopyFormat(&mixwfe->Format);
        CoTaskMemFree(mixwfe);
    } else if (device->primary_pwfx->wFormatTag == WAVE_FORMAT_PCM ||
               device->primary_pwfx->wFormatTag == WAVE_FORMAT_IEEE_FLOAT) {
        WAVEFORMATEX *wi = device->primary_pwfx;
        WAVEFORMATEXTENSIBLE *wfe;

        /* Convert to WAVEFORMATEXTENSIBLE */
        w = HeapAlloc(GetProcessHeap(), 0, sizeof(WAVEFORMATEXTENSIBLE));
        wfe = (WAVEFORMATEXTENSIBLE*)w;
        if (!wfe)
            return NULL;

        wfe->Format = *wi;
        w->wFormatTag = WAVE_FORMAT_EXTENSIBLE;
        w->cbSize = sizeof(*wfe) - sizeof(*w);
        wfe->dwChannelMask = 0;
        wfe->Samples.wValidBitsPerSample = 0;
        if (wi->wFormatTag == WAVE_FORMAT_IEEE_FLOAT) {
            w->wBitsPerSample = 32;
            wfe->SubFormat = KSDATAFORMAT_SUBTYPE_IEEE_FLOAT;
        } else
            wfe->SubFormat = KSDATAFORMAT_SUBTYPE_PCM;
    } else
        w = DSOUND_CopyFormat(device->primary_pwfx);

    if (!w)
        return NULL;

    hr = IAudioClient_IsFormatSupported(client, AUDCLNT_SHAREMODE_SHARED, w, (WAVEFORMATEX**)&retwfe);
    if (retwfe) {
        memcpy(w, retwfe, sizeof(WAVEFORMATEX) + retwfe->Format.cbSize);
        CoTaskMemFree(retwfe);
    }
    if (FAILED(hr)) {
        WARN("IsFormatSupported failed: %08x\n", hr);
        HeapFree(GetProcessHeap(), 0, w);
        return NULL;
    }
    return w;
}

HRESULT DSOUND_ReopenDevice(DirectSoundDevice *device, BOOL forcewave)
{
    HRESULT hres;
    REFERENCE_TIME period;
    UINT32 frames;
    DWORD period_ms;
    IAudioClient *client = NULL;
    IAudioRenderClient *render = NULL;
    IAudioStreamVolume *volume = NULL;
    DWORD fraglen, aclen;
    WAVEFORMATEX *wfx;

    TRACE("(%p, %d)\n", device, forcewave);

    hres = IMMDevice_Activate(device->mmdevice, &IID_IAudioClient,
            CLSCTX_INPROC_SERVER, NULL, (void **)&client);
    if(FAILED(hres)){
        WARN("Activate failed: %08x\n", hres);
        return hres;
    }

    wfx = DSOUND_WaveFormat(device, client, forcewave);
    if (!wfx)
        return DSERR_INVALIDPARAM;

    hres = IAudioClient_Initialize(client,
            AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_NOPERSIST |
            AUDCLNT_STREAMFLAGS_EVENTCALLBACK, 800000, 0, wfx, NULL);
    if(FAILED(hres)){
        IAudioClient_Release(client);
        ERR("Initialize failed: %08x\n", hres);
        return hres;
    }

    IAudioClient_SetEventHandle(client, device->sleepev);

    hres = IAudioClient_GetService(client, &IID_IAudioRenderClient, (void**)&render);
    if(FAILED(hres))
        goto err_service;

    hres = IAudioClient_GetService(client, &IID_IAudioStreamVolume, (void**)&volume);
    if(FAILED(hres))
        goto err_service;

    /* Now kick off the timer so the event fires periodically */
    IAudioClient_Start(client);
    IAudioClient_GetStreamLatency(client, &period);
    IAudioClient_GetBufferSize(client, &frames);
    period_ms = (period + 9999) / 10000;

    fraglen = MulDiv(wfx->nSamplesPerSec, period, 10000000) * wfx->nBlockAlign;
    aclen = frames * wfx->nBlockAlign;
    TRACE("period %u ms fraglen %u buflen %u\n", period_ms, fraglen, aclen);

    hres = DSOUND_PrimaryOpen(device, wfx, aclen, forcewave);
    if(FAILED(hres))
        goto err;

    DSOUND_ReleaseDevice(device);
    device->client = client;
    device->render = render;
    device->volume = volume;
    device->fraglen = fraglen;
    device->aclen = aclen;
    if (period_ms <= 15)
        device->sleeptime = period_ms * 5 / 2;
    else
        device->sleeptime = period_ms * 3 / 2;
    if (device->sleeptime < 10)
        device->sleeptime = 10;

    return S_OK;

err_service:
    WARN("GetService failed: %08x\n", hres);
err:
    if (volume)
        IAudioStreamVolume_Release(volume);
    if (render)
        IAudioRenderClient_Release(render);
    if (client)
        IAudioClient_Release(client);
    HeapFree(GetProcessHeap(), 0, wfx);
    return hres;
}

HRESULT DSOUND_PrimaryDestroy(DirectSoundDevice *device)
{
	TRACE("(%p)\n", device);

	/* **** */
	EnterCriticalSection(&(device->mixlock));

	if(device->primary && (device->primary->ref || device->primary->numIfaces))
		WARN("Destroying primary buffer while references held (%u %u)\n", device->primary->ref, device->primary->numIfaces);

	HeapFree(GetProcessHeap(), 0, device->primary);
	device->primary = NULL;

	HeapFree(GetProcessHeap(),0,device->primary_pwfx);
	HeapFree(GetProcessHeap(),0,device->pwfx);
	device->pwfx=NULL;

	LeaveCriticalSection(&(device->mixlock));
	/* **** */

	return DS_OK;
}

static DWORD DSOUND_GetFormatSize(LPCWAVEFORMATEX wfex)
{
	if (wfex->wFormatTag == WAVE_FORMAT_PCM)
		return sizeof(WAVEFORMATEX);
	else
		return sizeof(WAVEFORMATEX) + wfex->cbSize;
}

LPWAVEFORMATEX DSOUND_CopyFormat(LPCWAVEFORMATEX wfex)
{
	DWORD size = DSOUND_GetFormatSize(wfex);
	LPWAVEFORMATEX pwfx = HeapAlloc(GetProcessHeap(),0,size);
	if (pwfx == NULL) {
		WARN("out of memory\n");
	} else if (wfex->wFormatTag != WAVE_FORMAT_PCM) {
		CopyMemory(pwfx, wfex, size);
	} else {
		CopyMemory(pwfx, wfex, sizeof(PCMWAVEFORMAT));
		pwfx->cbSize=0;
		if (pwfx->nBlockAlign != pwfx->nChannels * pwfx->wBitsPerSample/8) {
			WARN("Fixing bad nBlockAlign (%u)\n", pwfx->nBlockAlign);
			pwfx->nBlockAlign  = pwfx->nChannels * pwfx->wBitsPerSample/8;
		}
		if (pwfx->nAvgBytesPerSec != pwfx->nSamplesPerSec * pwfx->nBlockAlign) {
			WARN("Fixing bad nAvgBytesPerSec (%u)\n", pwfx->nAvgBytesPerSec);
			pwfx->nAvgBytesPerSec  = pwfx->nSamplesPerSec * pwfx->nBlockAlign;
		}
	}
	return pwfx;
}

HRESULT primarybuffer_SetFormat(DirectSoundDevice *device, LPCWAVEFORMATEX passed_fmt)
{
	HRESULT err = S_OK;
	WAVEFORMATEX *old_fmt;
	WAVEFORMATEXTENSIBLE *fmtex, *passed_fmtex = (WAVEFORMATEXTENSIBLE*)passed_fmt;

	TRACE("(%p,%p)\n", device, passed_fmt);

	if (device->priolevel == DSSCL_NORMAL) {
		WARN("failed priority check!\n");
		return DSERR_PRIOLEVELNEEDED;
	}

	/* Let's be pedantic! */
	if (passed_fmt == NULL) {
		WARN("invalid parameter: passed_fmt==NULL!\n");
		return DSERR_INVALIDPARAM;
	}
	TRACE("(formattag=0x%04x,chans=%d,samplerate=%d,"
			  "bytespersec=%d,blockalign=%d,bitspersamp=%d,cbSize=%d)\n",
		  passed_fmt->wFormatTag, passed_fmt->nChannels, passed_fmt->nSamplesPerSec,
		  passed_fmt->nAvgBytesPerSec, passed_fmt->nBlockAlign,
		  passed_fmt->wBitsPerSample, passed_fmt->cbSize);

	if(passed_fmt->wBitsPerSample < 8 || passed_fmt->wBitsPerSample % 8 != 0 ||
			passed_fmt->nChannels == 0 || passed_fmt->nSamplesPerSec == 0 ||
			passed_fmt->nAvgBytesPerSec == 0 ||
			passed_fmt->nBlockAlign != passed_fmt->nChannels * passed_fmt->wBitsPerSample / 8)
		return DSERR_INVALIDPARAM;

	if(passed_fmt->wFormatTag == WAVE_FORMAT_EXTENSIBLE){
		if(passed_fmtex->Samples.wValidBitsPerSample > passed_fmtex->Format.wBitsPerSample)
			return DSERR_INVALIDPARAM;
	}

	/* **** */
	RtlAcquireResourceExclusive(&(device->buffer_list_lock), TRUE);
	EnterCriticalSection(&(device->mixlock));

	if (device->priolevel == DSSCL_WRITEPRIMARY) {
		old_fmt = device->primary_pwfx;
		device->primary_pwfx = DSOUND_CopyFormat(passed_fmt);
		fmtex = (WAVEFORMATEXTENSIBLE *)device->primary_pwfx;
		if (device->primary_pwfx == NULL) {
			err = DSERR_OUTOFMEMORY;
			goto out;
		}

		if (fmtex->Format.wFormatTag == WAVE_FORMAT_EXTENSIBLE &&
		    fmtex->Samples.wValidBitsPerSample == 0) {
			TRACE("Correcting 0 valid bits per sample\n");
			fmtex->Samples.wValidBitsPerSample = fmtex->Format.wBitsPerSample;
		}

		err = DSOUND_ReopenDevice(device, TRUE);
		if (FAILED(err)) {
			ERR("No formats could be opened\n");
			HeapFree(GetProcessHeap(), 0, device->primary_pwfx);
			device->primary_pwfx = old_fmt;
		} else
			HeapFree(GetProcessHeap(), 0, old_fmt);
	} else if (passed_fmt->wFormatTag == WAVE_FORMAT_PCM ||
		   passed_fmt->wFormatTag == WAVE_FORMAT_IEEE_FLOAT) {
		/* Fill in "real" values to primary_pwfx */
		WAVEFORMATEX *fmt = device->primary_pwfx;

		*fmt = *device->pwfx;
		fmtex = (void*)device->pwfx;

		if (IsEqualGUID(&fmtex->SubFormat, &KSDATAFORMAT_SUBTYPE_IEEE_FLOAT) &&
		    passed_fmt->wFormatTag == WAVE_FORMAT_IEEE_FLOAT) {
			fmt->wFormatTag = WAVE_FORMAT_IEEE_FLOAT;
			fmt->cbSize = 0;
		} else {
			fmt->wFormatTag = WAVE_FORMAT_PCM;
			fmt->wBitsPerSample = 16;
			fmt->cbSize = 0;
		}
		fmt->nBlockAlign = fmt->nChannels * fmt->wBitsPerSample / 8;
		fmt->nAvgBytesPerSec = fmt->nBlockAlign * fmt->nSamplesPerSec;
	} else {
		device->primary_pwfx = HeapReAlloc(GetProcessHeap(), 0, device->primary_pwfx, sizeof(*fmtex));
		memcpy(device->primary_pwfx, device->pwfx, sizeof(*fmtex));
	}

out:
	LeaveCriticalSection(&(device->mixlock));
	RtlReleaseResource(&(device->buffer_list_lock));
	/* **** */

	return err;
}

/*******************************************************************************
 *		PrimaryBuffer
 */
static inline IDirectSoundBufferImpl *impl_from_IDirectSoundBuffer(IDirectSoundBuffer *iface)
{
    /* IDirectSoundBuffer and IDirectSoundBuffer8 use the same iface. */
    return CONTAINING_RECORD(iface, IDirectSoundBufferImpl, IDirectSoundBuffer8_iface);
}

/* This sets this format for the primary buffer only */
static HRESULT WINAPI PrimaryBufferImpl_SetFormat(IDirectSoundBuffer *iface,
        const WAVEFORMATEX *wfex)
{
    IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
    TRACE("(%p,%p)\n", iface, wfex);
    return primarybuffer_SetFormat(This->device, wfex);
}

static HRESULT WINAPI PrimaryBufferImpl_SetVolume(IDirectSoundBuffer *iface, LONG vol)
{
	IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
	DirectSoundDevice *device = This->device;
	HRESULT hr;
	float lvol, rvol;

	TRACE("(%p,%d)\n", iface, vol);

	if (!(This->dsbd.dwFlags & DSBCAPS_CTRLVOLUME)) {
		WARN("control unavailable\n");
		return DSERR_CONTROLUNAVAIL;
	}

	if ((vol > DSBVOLUME_MAX) || (vol < DSBVOLUME_MIN)) {
		WARN("invalid parameter: vol = %d\n", vol);
		return DSERR_INVALIDPARAM;
	}

	/* **** */
	EnterCriticalSection(&device->mixlock);

	hr = IAudioStreamVolume_GetChannelVolume(device->volume, 0, &lvol);
	if(FAILED(hr)){
		LeaveCriticalSection(&device->mixlock);
		WARN("GetChannelVolume failed: %08x\n", hr);
		return hr;
	}

	if(device->pwfx->nChannels > 1){
		hr = IAudioStreamVolume_GetChannelVolume(device->volume, 1, &rvol);
		if(FAILED(hr)){
			LeaveCriticalSection(&device->mixlock);
			WARN("GetChannelVolume failed: %08x\n", hr);
			return hr;
		}
	}else
		rvol = 1;

	device->volpan.dwTotalLeftAmpFactor = ((UINT16)(lvol * (DWORD)0xFFFF));
	device->volpan.dwTotalRightAmpFactor = ((UINT16)(rvol * (DWORD)0xFFFF));

	DSOUND_AmpFactorToVolPan(&device->volpan);
	if (vol != device->volpan.lVolume) {
		device->volpan.lVolume=vol;
		DSOUND_RecalcVolPan(&device->volpan);
		lvol = (float)((DWORD)(device->volpan.dwTotalLeftAmpFactor & 0xFFFF) / (float)0xFFFF);
		hr = IAudioStreamVolume_SetChannelVolume(device->volume, 0, lvol);
		if(FAILED(hr)){
			LeaveCriticalSection(&device->mixlock);
			WARN("SetChannelVolume failed: %08x\n", hr);
			return hr;
		}

		if(device->pwfx->nChannels > 1){
			rvol = (float)((DWORD)(device->volpan.dwTotalRightAmpFactor & 0xFFFF) / (float)0xFFFF);
			hr = IAudioStreamVolume_SetChannelVolume(device->volume, 1, rvol);
			if(FAILED(hr)){
				LeaveCriticalSection(&device->mixlock);
				WARN("SetChannelVolume failed: %08x\n", hr);
				return hr;
			}
		}
	}

	LeaveCriticalSection(&(device->mixlock));
	/* **** */

	return DS_OK;
}

static HRESULT WINAPI PrimaryBufferImpl_GetVolume(IDirectSoundBuffer *iface, LONG *vol)
{
	IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
	DirectSoundDevice *device = This->device;
	float lvol, rvol;
	HRESULT hr;
	TRACE("(%p,%p)\n", iface, vol);

	if (!(This->dsbd.dwFlags & DSBCAPS_CTRLVOLUME)) {
		WARN("control unavailable\n");
		return DSERR_CONTROLUNAVAIL;
	}

	if (vol == NULL) {
		WARN("invalid parameter: vol = NULL\n");
		return DSERR_INVALIDPARAM;
	}

	EnterCriticalSection(&device->mixlock);

	hr = IAudioStreamVolume_GetChannelVolume(device->volume, 0, &lvol);
	if(FAILED(hr)){
		LeaveCriticalSection(&device->mixlock);
		WARN("GetChannelVolume failed: %08x\n", hr);
		return hr;
	}

	if(device->pwfx->nChannels > 1){
		hr = IAudioStreamVolume_GetChannelVolume(device->volume, 1, &rvol);
		if(FAILED(hr)){
			LeaveCriticalSection(&device->mixlock);
			WARN("GetChannelVolume failed: %08x\n", hr);
			return hr;
		}
	}else
		rvol = 1;

	device->volpan.dwTotalLeftAmpFactor = ((UINT16)(lvol * (DWORD)0xFFFF));
	device->volpan.dwTotalRightAmpFactor = ((UINT16)(rvol * (DWORD)0xFFFF));

	DSOUND_AmpFactorToVolPan(&device->volpan);
	*vol = device->volpan.lVolume;

	LeaveCriticalSection(&device->mixlock);

	return DS_OK;
}

static HRESULT WINAPI PrimaryBufferImpl_SetFrequency(IDirectSoundBuffer *iface, DWORD freq)
{
        IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
	TRACE("(%p,%d)\n",This,freq);

	/* You cannot set the frequency of the primary buffer */
	WARN("control unavailable\n");
	return DSERR_CONTROLUNAVAIL;
}

static HRESULT WINAPI PrimaryBufferImpl_Play(IDirectSoundBuffer *iface, DWORD reserved1,
        DWORD reserved2, DWORD flags)
{
        IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
        DirectSoundDevice *device = This->device;
	TRACE("(%p,%08x,%08x,%08x)\n", iface, reserved1, reserved2, flags);

	if (!(flags & DSBPLAY_LOOPING)) {
		WARN("invalid parameter: flags = %08x\n", flags);
		return DSERR_INVALIDPARAM;
	}

	/* **** */
	EnterCriticalSection(&(device->mixlock));

	if (device->priolevel == DSSCL_WRITEPRIMARY && device->client)
		IAudioClient_Start(device->client);
	device->stopped = 0;

	LeaveCriticalSection(&(device->mixlock));
	/* **** */

	return DS_OK;
}

static HRESULT WINAPI PrimaryBufferImpl_Stop(IDirectSoundBuffer *iface)
{
        IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
        DirectSoundDevice *device = This->device;
	TRACE("(%p)\n", iface);

	/* **** */
	EnterCriticalSection(&(device->mixlock));

	if (device->priolevel == DSSCL_WRITEPRIMARY && device->client)
		IAudioClient_Stop(device->client);
	device->stopped = 1;

	LeaveCriticalSection(&(device->mixlock));
	/* **** */

	return DS_OK;
}

static ULONG WINAPI PrimaryBufferImpl_AddRef(IDirectSoundBuffer *iface)
{
    IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
    ULONG ref = InterlockedIncrement(&(This->ref));
    TRACE("(%p) ref was %d\n", This, ref - 1);
    if(ref == 1)
        InterlockedIncrement(&This->numIfaces);
    return ref;
}

/* Decreases *out by 1 to no less than 0.
 * Returns the new value of *out. */
LONG capped_refcount_dec(LONG *out)
{
    LONG ref, oldref;
    do {
        ref = *out;
        if(!ref)
            return 0;
        oldref = InterlockedCompareExchange(out, ref - 1, ref);
    } while(oldref != ref);
    return ref - 1;
}

static ULONG WINAPI PrimaryBufferImpl_Release(IDirectSoundBuffer *iface)
{
    IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
    ULONG ref;

    ref = capped_refcount_dec(&This->ref);
    if(!ref)
        capped_refcount_dec(&This->numIfaces);

    TRACE("(%p) primary ref is now %d\n", This, ref);

    return ref;
}

static HRESULT WINAPI PrimaryBufferImpl_GetCurrentPosition(IDirectSoundBuffer *iface,
        DWORD *playpos, DWORD *writepos)
{
	HRESULT	hres = DS_OK;
	UINT32 pad = 0;
	UINT32 mixpos;
        IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
        DirectSoundDevice *device = This->device;
	TRACE("(%p,%p,%p)\n", iface, playpos, writepos);

	/* **** */
	EnterCriticalSection(&(device->mixlock));

	if (device->client)
		hres = IAudioClient_GetCurrentPadding(device->client, &pad);
	if (hres != DS_OK) {
		WARN("IAudioClient_GetCurrentPadding failed\n");
		LeaveCriticalSection(&(device->mixlock));
		return hres;
	}
	mixpos = (device->playpos + pad * device->pwfx->nBlockAlign) % device->buflen;
	if (playpos)
		*playpos = mixpos;
	if (writepos) {
		*writepos = mixpos;
		if (!device->stopped) {
			/* apply the documented 10ms lead to writepos */
			*writepos += device->writelead;
			*writepos %= device->buflen;
		}
	}

	LeaveCriticalSection(&(device->mixlock));
	/* **** */

	TRACE("playpos = %d, writepos = %d (%p, time=%d)\n", playpos?*playpos:0, writepos?*writepos:0, device, GetTickCount());
	return DS_OK;
}

static HRESULT WINAPI PrimaryBufferImpl_GetStatus(IDirectSoundBuffer *iface, DWORD *status)
{
        IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
        DirectSoundDevice *device = This->device;
	TRACE("(%p,%p)\n", iface, status);

	if (status == NULL) {
		WARN("invalid parameter: status == NULL\n");
		return DSERR_INVALIDPARAM;
	}

	*status = 0;
	if (!device->stopped)
		*status |= DSBSTATUS_PLAYING | DSBSTATUS_LOOPING;

	TRACE("status=%x\n", *status);
	return DS_OK;
}


static HRESULT WINAPI PrimaryBufferImpl_GetFormat(IDirectSoundBuffer *iface, WAVEFORMATEX *lpwf,
        DWORD wfsize, DWORD *wfwritten)
{
    DWORD size;
    IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
    DirectSoundDevice *device = This->device;
    TRACE("(%p,%p,%d,%p)\n", iface, lpwf, wfsize, wfwritten);

    size = sizeof(WAVEFORMATEX) + device->primary_pwfx->cbSize;

    if (lpwf) {	/* NULL is valid */
        if (wfsize >= size) {
            CopyMemory(lpwf,device->primary_pwfx,size);
            if (wfwritten)
                *wfwritten = size;
        } else {
            WARN("invalid parameter: wfsize too small\n");
            if (wfwritten)
                *wfwritten = 0;
            return DSERR_INVALIDPARAM;
        }
    } else {
        if (wfwritten)
            *wfwritten = sizeof(WAVEFORMATEX) + device->primary_pwfx->cbSize;
        else {
            WARN("invalid parameter: wfwritten == NULL\n");
            return DSERR_INVALIDPARAM;
        }
    }

    return DS_OK;
}

static HRESULT WINAPI PrimaryBufferImpl_Lock(IDirectSoundBuffer *iface, DWORD writecursor,
        DWORD writebytes, void **lplpaudioptr1, DWORD *audiobytes1, void **lplpaudioptr2,
        DWORD *audiobytes2, DWORD flags)
{
	HRESULT hres;
        IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
        DirectSoundDevice *device = This->device;
	TRACE("(%p,%d,%d,%p,%p,%p,%p,0x%08x) at %d\n",
		iface,
		writecursor,
		writebytes,
		lplpaudioptr1,
		audiobytes1,
		lplpaudioptr2,
		audiobytes2,
		flags,
		GetTickCount()
	);

        if (!audiobytes1)
            return DSERR_INVALIDPARAM;

	if (device->priolevel != DSSCL_WRITEPRIMARY) {
		WARN("failed priority check!\n");
		return DSERR_PRIOLEVELNEEDED;
	}

        /* when this flag is set, writecursor is meaningless and must be calculated */
	if (flags & DSBLOCK_FROMWRITECURSOR) {
		/* GetCurrentPosition does too much magic to duplicate here */
		hres = IDirectSoundBuffer_GetCurrentPosition(iface, NULL, &writecursor);
		if (hres != DS_OK) {
			WARN("IDirectSoundBuffer_GetCurrentPosition failed\n");
			return hres;
		}
	}

        /* when this flag is set, writebytes is meaningless and must be set */
	if (flags & DSBLOCK_ENTIREBUFFER)
		writebytes = device->buflen;

        if (writecursor >= device->buflen) {
                WARN("Invalid parameter, writecursor: %u >= buflen: %u\n",
		     writecursor, device->buflen);
                return DSERR_INVALIDPARAM;
        }

        if (writebytes > device->buflen) {
                WARN("Invalid parameter, writebytes: %u > buflen: %u\n",
		     writebytes, device->buflen);
                return DSERR_INVALIDPARAM;
        }

	if (writecursor+writebytes <= device->buflen) {
		*(LPBYTE*)lplpaudioptr1 = device->buffer+writecursor;
		*audiobytes1 = writebytes;
		if (lplpaudioptr2)
			*(LPBYTE*)lplpaudioptr2 = NULL;
		if (audiobytes2)
			*audiobytes2 = 0;
		TRACE("->%d.0\n",writebytes);
	} else {
		*(LPBYTE*)lplpaudioptr1 = device->buffer+writecursor;
		*audiobytes1 = device->buflen-writecursor;
		if (lplpaudioptr2)
			*(LPBYTE*)lplpaudioptr2 = device->buffer;
		if (audiobytes2)
			*audiobytes2 = writebytes-(device->buflen-writecursor);
		TRACE("->%d.%d\n",*audiobytes1,audiobytes2?*audiobytes2:0);
	}
	return DS_OK;
}

static HRESULT WINAPI PrimaryBufferImpl_SetCurrentPosition(IDirectSoundBuffer *iface, DWORD newpos)
{
        IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
	TRACE("(%p,%d)\n",This,newpos);

	/* You cannot set the position of the primary buffer */
	WARN("invalid call\n");
	return DSERR_INVALIDCALL;
}

static HRESULT WINAPI PrimaryBufferImpl_SetPan(IDirectSoundBuffer *iface, LONG pan)
{
	IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
	DirectSoundDevice *device = This->device;
	float lvol, rvol;
	HRESULT hr;
	TRACE("(%p,%d)\n", iface, pan);

	if (!(This->dsbd.dwFlags & DSBCAPS_CTRLPAN)) {
		WARN("control unavailable\n");
		return DSERR_CONTROLUNAVAIL;
	}

	if ((pan > DSBPAN_RIGHT) || (pan < DSBPAN_LEFT)) {
		WARN("invalid parameter: pan = %d\n", pan);
		return DSERR_INVALIDPARAM;
	}

	/* **** */
	EnterCriticalSection(&device->mixlock);

	hr = IAudioStreamVolume_GetChannelVolume(device->volume, 0, &lvol);
	if(FAILED(hr)){
		LeaveCriticalSection(&device->mixlock);
		WARN("GetChannelVolume failed: %08x\n", hr);
		return hr;
	}

	if(device->pwfx->nChannels > 1){
		hr = IAudioStreamVolume_GetChannelVolume(device->volume, 1, &rvol);
		if(FAILED(hr)){
			LeaveCriticalSection(&device->mixlock);
			WARN("GetChannelVolume failed: %08x\n", hr);
			return hr;
		}
	}else
		rvol = 1;

	device->volpan.dwTotalLeftAmpFactor = ((UINT16)(lvol * (DWORD)0xFFFF));
	device->volpan.dwTotalRightAmpFactor = ((UINT16)(rvol * (DWORD)0xFFFF));

	DSOUND_AmpFactorToVolPan(&device->volpan);
	if (pan != device->volpan.lPan) {
		device->volpan.lPan=pan;
		DSOUND_RecalcVolPan(&device->volpan);

		lvol = (float)((DWORD)(device->volpan.dwTotalLeftAmpFactor & 0xFFFF) / (float)0xFFFF);
		hr = IAudioStreamVolume_SetChannelVolume(device->volume, 0, lvol);
		if(FAILED(hr)){
			LeaveCriticalSection(&device->mixlock);
			WARN("SetChannelVolume failed: %08x\n", hr);
			return hr;
		}

		if(device->pwfx->nChannels > 1){
			rvol = (float)((DWORD)(device->volpan.dwTotalRightAmpFactor & 0xFFFF) / (float)0xFFFF);
			hr = IAudioStreamVolume_SetChannelVolume(device->volume, 1, rvol);
			if(FAILED(hr)){
				LeaveCriticalSection(&device->mixlock);
				WARN("SetChannelVolume failed: %08x\n", hr);
				return hr;
			}
		}
	}

	LeaveCriticalSection(&device->mixlock);
	/* **** */

	return DS_OK;
}

static HRESULT WINAPI PrimaryBufferImpl_GetPan(IDirectSoundBuffer *iface, LONG *pan)
{
	IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
	DirectSoundDevice *device = This->device;
	float lvol, rvol;
	HRESULT hr;
	TRACE("(%p,%p)\n", iface, pan);

	if (!(This->dsbd.dwFlags & DSBCAPS_CTRLPAN)) {
		WARN("control unavailable\n");
		return DSERR_CONTROLUNAVAIL;
	}

	if (pan == NULL) {
		WARN("invalid parameter: pan == NULL\n");
		return DSERR_INVALIDPARAM;
	}

	EnterCriticalSection(&device->mixlock);

	hr = IAudioStreamVolume_GetChannelVolume(device->volume, 0, &lvol);
	if(FAILED(hr)){
		LeaveCriticalSection(&device->mixlock);
		WARN("GetChannelVolume failed: %08x\n", hr);
		return hr;
	}

	if(device->pwfx->nChannels > 1){
		hr = IAudioStreamVolume_GetChannelVolume(device->volume, 1, &rvol);
		if(FAILED(hr)){
			LeaveCriticalSection(&device->mixlock);
			WARN("GetChannelVolume failed: %08x\n", hr);
			return hr;
		}
	}else
		rvol = 1;

	device->volpan.dwTotalLeftAmpFactor = ((UINT16)(lvol * (DWORD)0xFFFF));
	device->volpan.dwTotalRightAmpFactor = ((UINT16)(rvol * (DWORD)0xFFFF));

	DSOUND_AmpFactorToVolPan(&device->volpan);
	*pan = device->volpan.lPan;

	LeaveCriticalSection(&device->mixlock);

	return DS_OK;
}

static HRESULT WINAPI PrimaryBufferImpl_Unlock(IDirectSoundBuffer *iface, void *p1, DWORD x1,
        void *p2, DWORD x2)
{
        IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
        DirectSoundDevice *device = This->device;
	TRACE("(%p,%p,%d,%p,%d)\n", iface, p1, x1, p2, x2);

	if (device->priolevel != DSSCL_WRITEPRIMARY) {
		WARN("failed priority check!\n");
		return DSERR_PRIOLEVELNEEDED;
	}

    if((p1 && ((BYTE*)p1 < device->buffer ||
                    (BYTE*)p1 >= device->buffer + device->buflen)) ||
            (p2 && ((BYTE*)p2 < device->buffer ||
                    (BYTE*)p2 >= device->buffer + device->buflen)))
        return DSERR_INVALIDPARAM;

	return DS_OK;
}

static HRESULT WINAPI PrimaryBufferImpl_Restore(IDirectSoundBuffer *iface)
{
        IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
	FIXME("(%p):stub\n",This);
	return DS_OK;
}

static HRESULT WINAPI PrimaryBufferImpl_GetFrequency(IDirectSoundBuffer *iface, DWORD *freq)
{
        IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
        DirectSoundDevice *device = This->device;
	TRACE("(%p,%p)\n", iface, freq);

	if (freq == NULL) {
		WARN("invalid parameter: freq == NULL\n");
		return DSERR_INVALIDPARAM;
	}

	if (!(This->dsbd.dwFlags & DSBCAPS_CTRLFREQUENCY)) {
		WARN("control unavailable\n");
		return DSERR_CONTROLUNAVAIL;
	}

	*freq = device->pwfx->nSamplesPerSec;
	TRACE("-> %d\n", *freq);

	return DS_OK;
}

static HRESULT WINAPI PrimaryBufferImpl_Initialize(IDirectSoundBuffer *iface, IDirectSound *dsound,
        const DSBUFFERDESC *dbsd)
{
        IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
	WARN("(%p) already initialized\n", This);
	return DSERR_ALREADYINITIALIZED;
}

static HRESULT WINAPI PrimaryBufferImpl_GetCaps(IDirectSoundBuffer *iface, DSBCAPS *caps)
{
        IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);
        DirectSoundDevice *device = This->device;
  	TRACE("(%p,%p)\n", iface, caps);

	if (caps == NULL) {
		WARN("invalid parameter: caps == NULL\n");
		return DSERR_INVALIDPARAM;
	}

	if (caps->dwSize < sizeof(*caps)) {
		WARN("invalid parameter: caps->dwSize = %d\n", caps->dwSize);
		return DSERR_INVALIDPARAM;
	}

	caps->dwFlags = This->dsbd.dwFlags;
	caps->dwBufferBytes = device->buflen;

	/* Windows reports these as zero */
	caps->dwUnlockTransferRate = 0;
	caps->dwPlayCpuOverhead = 0;

	return DS_OK;
}

static HRESULT WINAPI PrimaryBufferImpl_QueryInterface(IDirectSoundBuffer *iface, REFIID riid,
        void **ppobj)
{
        IDirectSoundBufferImpl *This = impl_from_IDirectSoundBuffer(iface);

	TRACE("(%p,%s,%p)\n", iface, debugstr_guid(riid), ppobj);

	if (ppobj == NULL) {
		WARN("invalid parameter\n");
		return E_INVALIDARG;
	}

	*ppobj = NULL;	/* assume failure */

	if ( IsEqualGUID(riid, &IID_IUnknown) ||
	     IsEqualGUID(riid, &IID_IDirectSoundBuffer) ) {
		IDirectSoundBuffer_AddRef(iface);
		*ppobj = iface;
		return S_OK;
	}

	/* DirectSoundBuffer and DirectSoundBuffer8 are different and */
	/* a primary buffer can't have a DirectSoundBuffer8 interface */
	if ( IsEqualGUID( &IID_IDirectSoundBuffer8, riid ) ) {
		WARN("app requested DirectSoundBuffer8 on primary buffer\n");
		return E_NOINTERFACE;
	}

	if ( IsEqualGUID( &IID_IDirectSoundNotify, riid ) ) {
		ERR("app requested IDirectSoundNotify on primary buffer\n");
		/* FIXME: should we support this? */
		return E_NOINTERFACE;
	}

	if ( IsEqualGUID( &IID_IDirectSound3DBuffer, riid ) ) {
		ERR("app requested IDirectSound3DBuffer on primary buffer\n");
		return E_NOINTERFACE;
	}

        if ( IsEqualGUID( &IID_IDirectSound3DListener, riid ) ) {
                *ppobj = &This->IDirectSound3DListener_iface;
                IDirectSound3DListener_AddRef(&This->IDirectSound3DListener_iface);
                return S_OK;
	}

	if ( IsEqualGUID( &IID_IKsPropertySet, riid ) ) {
                *ppobj = &This->IKsPropertySet_iface;
                IKsPropertySet_AddRef(&This->IKsPropertySet_iface);
                return S_OK;
	}

	FIXME( "Unknown IID %s\n", debugstr_guid( riid ) );
	return E_NOINTERFACE;
}

static const IDirectSoundBufferVtbl dspbvt =
{
	PrimaryBufferImpl_QueryInterface,
	PrimaryBufferImpl_AddRef,
	PrimaryBufferImpl_Release,
	PrimaryBufferImpl_GetCaps,
	PrimaryBufferImpl_GetCurrentPosition,
	PrimaryBufferImpl_GetFormat,
	PrimaryBufferImpl_GetVolume,
	PrimaryBufferImpl_GetPan,
        PrimaryBufferImpl_GetFrequency,
	PrimaryBufferImpl_GetStatus,
	PrimaryBufferImpl_Initialize,
	PrimaryBufferImpl_Lock,
	PrimaryBufferImpl_Play,
	PrimaryBufferImpl_SetCurrentPosition,
	PrimaryBufferImpl_SetFormat,
	PrimaryBufferImpl_SetVolume,
	PrimaryBufferImpl_SetPan,
	PrimaryBufferImpl_SetFrequency,
	PrimaryBufferImpl_Stop,
	PrimaryBufferImpl_Unlock,
	PrimaryBufferImpl_Restore
};

HRESULT primarybuffer_create(DirectSoundDevice *device, IDirectSoundBufferImpl **ppdsb,
	const DSBUFFERDESC *dsbd)
{
	IDirectSoundBufferImpl *dsb;
	TRACE("%p,%p,%p)\n",device,ppdsb,dsbd);

	if (dsbd->lpwfxFormat) {
		WARN("invalid parameter: dsbd->lpwfxFormat != NULL\n");
		*ppdsb = NULL;
		return DSERR_INVALIDPARAM;
	}

	dsb = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*dsb));

	if (dsb == NULL) {
		WARN("out of memory\n");
		*ppdsb = NULL;
		return DSERR_OUTOFMEMORY;
	}

        dsb->ref = 0;
        dsb->ref3D = 0;
        dsb->refiks = 0;
        dsb->numIfaces = 0;
	dsb->device = device;
	dsb->IDirectSoundBuffer8_iface.lpVtbl = (IDirectSoundBuffer8Vtbl *)&dspbvt;
        dsb->IDirectSound3DListener_iface.lpVtbl = &ds3dlvt;
        dsb->IKsPropertySet_iface.lpVtbl = &iksbvt;
	dsb->dsbd = *dsbd;

        /* IDirectSound3DListener */
        device->ds3dl.dwSize = sizeof(DS3DLISTENER);
        device->ds3dl.vPosition.x = 0.0;
        device->ds3dl.vPosition.y = 0.0;
        device->ds3dl.vPosition.z = 0.0;
        device->ds3dl.vVelocity.x = 0.0;
        device->ds3dl.vVelocity.y = 0.0;
        device->ds3dl.vVelocity.z = 0.0;
        device->ds3dl.vOrientFront.x = 0.0;
        device->ds3dl.vOrientFront.y = 0.0;
        device->ds3dl.vOrientFront.z = 1.0;
        device->ds3dl.vOrientTop.x = 0.0;
        device->ds3dl.vOrientTop.y = 1.0;
        device->ds3dl.vOrientTop.z = 0.0;
        device->ds3dl.flDistanceFactor = DS3D_DEFAULTDISTANCEFACTOR;
        device->ds3dl.flRolloffFactor = DS3D_DEFAULTROLLOFFFACTOR;
        device->ds3dl.flDopplerFactor = DS3D_DEFAULTDOPPLERFACTOR;
        device->ds3dl_need_recalc = TRUE;

	TRACE("Created primary buffer at %p\n", dsb);
	TRACE("(formattag=0x%04x,chans=%d,samplerate=%d,"
		"bytespersec=%d,blockalign=%d,bitspersamp=%d,cbSize=%d)\n",
		device->pwfx->wFormatTag, device->pwfx->nChannels,
                device->pwfx->nSamplesPerSec, device->pwfx->nAvgBytesPerSec,
                device->pwfx->nBlockAlign, device->pwfx->wBitsPerSample,
                device->pwfx->cbSize);

        IDirectSoundBuffer_AddRef(&dsb->IDirectSoundBuffer8_iface);
	*ppdsb = dsb;
	return S_OK;
}
