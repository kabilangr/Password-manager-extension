// Content Script for CipherVault Extension
// Runs on all web pages

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message: { action: string; secretId: string }) => {
    if (message.action === 'FILL_PASSWORD') {
        fillPasswordField(message.secretId)
    }
})

function fillPasswordField(secretId: string) {
    const passwordFields = document.querySelectorAll('input[type="password"]')

    if (passwordFields.length === 0) {
        console.log("CipherVault: No password field found")
        return
    }

    alert(`CipherVault: Would fill secret ${secretId}.\nIn production, this would auto-fill your credentials.`)
}

function injectIcons() {
    const passwordFields = document.querySelectorAll('input[type="password"]:not([data-ciphervault])')

    passwordFields.forEach((field) => {
        field.setAttribute('data-ciphervault', 'true')

        const iconBtn = document.createElement('div')
        iconBtn.className = 'ciphervault-icon'
        iconBtn.innerHTML = '🔐'
        iconBtn.style.cssText = `
            position: absolute;
            right: 8px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            font-size: 16px;
            z-index: 9999;
        `

        iconBtn.onclick = (e) => {
            e.preventDefault()
            e.stopPropagation()
            chrome.runtime.sendMessage({ action: 'OPEN_POPUP' })
        }

        const wrapper = document.createElement('div')
        wrapper.style.cssText = 'position:relative; display:inline-block; width:100%;'
        field.parentNode?.insertBefore(wrapper, field)
        wrapper.appendChild(field)
        wrapper.appendChild(iconBtn)
    })
}

injectIcons()

const observer = new MutationObserver(() => {
    injectIcons()
})

observer.observe(document.body, { childList: true, subtree: true })
