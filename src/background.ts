// Background Service Worker for CipherVault Extension

chrome.runtime.onMessage.addListener((message: { action: string }) => {
    if (message.action === 'OPEN_POPUP') {
        chrome.action.setBadgeText({ text: '!' })
        chrome.action.setBadgeBackgroundColor({ color: '#6366f1' })
    }

    if (message.action === 'CLEAR_BADGE') {
        chrome.action.setBadgeText({ text: '' })
    }
})

chrome.runtime.onInstalled.addListener(() => {
    console.log('CipherVault Extension installed')
})

export async function storeMasterKeyHash(keyHash: string) {
    await chrome.storage.session.set({ masterKeyHash: keyHash })
}

export async function getMasterKeyHash(): Promise<string | null> {
    const result = await chrome.storage.session.get('masterKeyHash')
    return (result.masterKeyHash as string) || null
}
