function isRedirect(location) {
    return (location.search.indexOf('code=') !== -1 && location.search.indexOf('state=') !== -1) ||
        location.search.indexOf('error=') !== -1
}

function launchUrlAndListenForRedirects(url) {
    let loginWindow = window.open(url, 'login')
    let loginCompletion = new Promise( (resolve, reject) => {
        loginWindow.addEventListener('beforeunload', (event) => {
            let target = event.currentTarget
            if (target.closed) {
                reject()
            } else if (isRedirect(target.location)) {
                resolve(target.location.href)
                loginWindow.close();
            }
        })
    })
    return loginCompletion
}