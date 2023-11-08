class SecurityFilterChain{

    generateRandomToken =()=> {
        // Generate a random token using the crypto API
        const randomBytes = new Uint8Array(16);
        crypto.getRandomValues(randomBytes);
        const token = Array.from(randomBytes)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');
        return `${token.substr(0, 6)}-${token.substr(8, 8)}-${token.substr(12, 4)}-${token.substr(12, 6)}-${token.substr(20)}`;
    }
    jwt = async () => {
        var response, data, readText;
        var headers = new Headers();
        headers.append('Authorization', 'Bearer '+this.generateRandomToken()+'');
        response = await fetch(root_url + "api/collect?iat=sort&action=true&target=central&v2=rgstr", { headers: headers });
        if (!response.ok) {
            throw new Error(`Network response was not OK: ${response.status}`);
        } else {
            // Parse the response as text
            data = await response.text();
            readText = JSON.parse(data);
           return (readText);
        }
    }
}

export default SecurityFilterChain;