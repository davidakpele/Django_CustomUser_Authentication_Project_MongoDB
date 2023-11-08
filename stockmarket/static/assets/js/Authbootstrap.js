const generateRandomToken =()=> {
    // Generate a random token using the crypto API
    const randomBytes = new Uint8Array(16);
    crypto.getRandomValues(randomBytes);
    const token = Array.from(randomBytes)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
    return `${token.substr(0, 6)}-${token.substr(8, 8)}-${token.substr(12, 4)}-${token.substr(12, 6)}-${token.substr(20)}`;
}
function csrfmiddlewaretoken(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const charactersLength = characters.length;
  let token = '';

  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * charactersLength);
    token += characters.charAt(randomIndex);
  }

  return token;
}
const csrfTokenInput = csrfmiddlewaretoken(64);

const refreshjwtToken = async () => {
    var response, data, readText;
    var headers = new Headers();
    headers.append('Authorization', 'Bearer ' + generateRandomToken() + '');
    response = await fetch("/api/collect", { method: 'GET', headers: headers });
    if (!response.ok) {
        throw new Error(`Network response was not OK: ${response.status}`);
    } else {
        data = await response.text();
        readText = JSON.parse(data);
        var api = readText.api.aot.access_token
        var imprint = readText.api.aot.imprint
        var syphine = readText.api.aot.syphine
        var asyc = readText.asyc
        var jwt = readText.jwt
        var apt = readText.post_add
        localStorage.setItem('aot', api);
        localStorage.setItem('imprint', imprint);
        localStorage.setItem('syphine', syphine);
        localStorage.setItem('asyc', asyc);
        localStorage.setItem('jwtToken', jwt);
        localStorage.setItem('apt', apt);
    }
   
}
function clearAllCookies() {
   $.each(document.cookie.split(/; */), function() {
    var cookie = this.split('=');
    var name = cookie[0];
    document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
  });
}

$('document').ready(function () {
    $('.logout').click(function (e) {
        e.preventDefault();
        let xhr, get_init, obj;
        xhr = new XMLHttpRequest();
        xhr.open('GET', '/logout/');
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4 && xhr.status === 200) {
                get_init = xhr.response;
                obj = JSON.parse(get_init);
                if (obj.status === 200) {
                    window.location = '/';  
                    localStorage.clear();
                    
                    if ($.cookie("jwt") != null) {
                        clearAllCookies();
                        $.cookie("jwt", null, { path: '/' });
                        $.removeCookie('jwt', { path: '/' });
                        $.removeCookie("Name");
                    }
                }
            return false;
            }
        }
        xhr.send();
    
        
    })
})
// Schedule the refresh every 30 seconds
setInterval(refreshjwtToken, 30000); // 30,000 milliseconds = 30 seconds