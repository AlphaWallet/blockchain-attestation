import {SignedDevconTicket} from "../../SignedDevconTicket";
// import {Authenticator} from "../../crypto/src/Authenticator";

export class Negotiator {
    // other code
    constructor(filter = {}, options = {}) {
        let XMLconfig = {
            attestationOrigin: "https://stage.attestation.id",
            tokensOrigin: "https://devcontickets.herokuapp.com/outlet/",
            tokenUrlName: 'ticket',
            tokenSecretName: 'secret',
            unsignedTokenDataName: 'ticket',
            // tokenParserUrl: '',
            tokenParser: SignedDevconTicket,
            localStorageItemName: 'dcTokens'
        };
        this.queuedCommand = false;

        this.filter = filter;
        this.debug = 0;
        this.hideTokensIframe = 1;
        this.tokensOrigin = XMLconfig.tokensOrigin;
        this.attestationOrigin = XMLconfig.attestationOrigin;
        this.tokenUrlName = XMLconfig.tokenUrlName;
        this.tokenSecretName = XMLconfig.tokenSecretName;
        this.unsignedTokenDataName = XMLconfig.unsignedTokenDataName;
        this.tokenParser = XMLconfig.tokenParser;
        this.localStorageItemName = XMLconfig.localStorageItemName;

        if (options.hasOwnProperty('debug')) this.debug = options.debug;
        if (options.hasOwnProperty('attestationOrigin')) this.attestationOrigin = options.attestationOrigin;
        if (options.hasOwnProperty('tokensOrigin')) this.tokensOrigin = options.tokensOrigin;

        this.isTokenOriginWebsite = false;

        if (this.attestationOrigin) {
            // if attestationOrigin filled then token need attestaion
            let currentURL = new URL(window.location.href);
            let tokensOriginURL = new URL(this.tokensOrigin);

            if (currentURL.origin === tokensOriginURL.origin) {
                console.log('this is tokenOrigin. fire listener and read params');
                // its tokens website, where tokens saved in localStorage
                // lets chech url params and save token data to the local storage
                this.isTokenOriginWebsite = true;
                this.readMagicUrl();
            }
        }

        // do we inside iframe?
        if (window !== window.parent){
            this.debug && console.log('negotiator: its iframe, lets return tokens to the parent');

            // its iframe, listen for requests
            this.attachPostMessageListener(this.listenForParentMessages.bind(this))

            // send ready message to start interaction
            let referrer = new URL(document.referrer);
            window.parent.postMessage({iframeCommand: "iframeReady", iframeData: ''}, referrer.origin);
        }
    }

    listenForParentMessages(event){

        // listen only parent
        let referrer = new URL(document.referrer);
        if (event.origin !== referrer.origin) {
            return;
        }

        // console.log('iframe: event = ', event.data);

        // parentCommand+parentData required for interaction
        if (
            typeof event.data.parentCommand === "undefined"
            || typeof event.data.parentData === "undefined"
        ) {
            return;
        }

        // parentCommand contain command code
        let command = event.data.parentCommand;

        // parentData contains command content (token to sign or empty object)
        let data = event.data.parentData;

        console.log('iframe: command, data = ', command, data);

        switch (command) {
            case "signToken":
                console.log('let Auth data:', data);
                if (typeof window.Authenticator === "undefined"){
                    console.log('Authenticator not defined.');
                    return;
                }

                let rawTokenData = this.getRawToken(data);

                // console.log('rawTokenData: ',rawTokenData);

                let base64ticket = rawTokenData.token;
                let ticketSecret = rawTokenData.secret;
                this.authenticator = new Authenticator(this);
                this.authenticator.getAuthenticationBlob({
                    ticketBlob: base64ticket,
                    ticketSecret: ticketSecret,
                    attestationOrigin: this.attestationOrigin,
                },
                        res => {
                    console.log('sign result:',res);
                    window.parent.postMessage({iframeCommand: "useTokenData", iframeData: {useToken: res, message: '', success: !!res}}, referrer.origin);
                });
                break;
            case "tokensList":
                // TODO update
                console.log('let return tokens');
                this.returnTokensToParent();
                break;

            default:
        }
    }

    commandDisplayIframe(){
        let referrer = new URL(document.referrer);
        window.parent.postMessage({iframeCommand: "iframeWrap", iframeData: 'show'}, referrer.origin);
    }

    commandHideIframe(){
        let referrer = new URL(document.referrer);
        window.parent.postMessage({iframeCommand: "iframeWrap", iframeData: 'hide'}, referrer.origin);
    }

    returnTokensToParent(){
        let tokensOutput = this.readTokens();
        if (tokensOutput.success && !tokensOutput.noTokens) {
            let decodedTokens = this.decodeTokens(tokensOutput.tokens);
            let filteredTokens = this.filterTokens(decodedTokens);
            tokensOutput.tokens = filteredTokens;
        }
        let referrer = new URL(document.referrer);
        window.parent.postMessage({iframeCommand: "tokensData", iframeData: tokensOutput}, referrer.origin);
    }

    readMagicUrl() {
        const urlParams = new URLSearchParams(window.location.search);
        const tokenFromQuery = urlParams.get(this.tokenUrlName);
        const secretFromQuery = urlParams.get(this.tokenSecretName);

        if (! (tokenFromQuery && secretFromQuery) ) {
            return;
        }

        // Get the current Storage Tokens
        let tokensOutput = this.readTokens();
        let tokens = [];

        let isNewQueryTicket = true;

        if (!tokensOutput.noTokens) {
            // Build new list of tickets from current and query ticket { ticket, secret }
            tokens = tokensOutput.tokens;

            tokens.map(tokenData => {
                if (tokenData.token === tokenFromQuery) {
                    isNewQueryTicket = false;
                }
            });

        }

        // Add ticket if new
        // if (isNewQueryTicket && tokenFromQuery && secretFromQuery) {
        if (isNewQueryTicket) {
            tokens.push({token: tokenFromQuery, secret: secretFromQuery}); // new raw object
        }
        // Set New tokens list raw only, websters will be decoded each time
        localStorage.setItem(this.localStorageItemName, JSON.stringify(tokens));
    }

    /*
     * Return token objects satisfying the current negotiator's requirements
     */
    filterTokens(decodedTokens, filter = {}) {
        if (Object.keys(filter).length == 0) {
            filter = this.filter;
        }
        let res = [];
        if (
            decodedTokens.length
            && typeof filter === "object"
            && Object.keys(filter).length
        ) {
            let filterKeys = Object.keys(filter);
            decodedTokens.forEach(token => {
                let fitFilter = 1;
                this.debug && console.log('test token:',token);
                filterKeys.forEach(key => {
                    if (token[key].toString() != filter[key].toString()) fitFilter = 0;
                })
                if (fitFilter) {
                    res.push(token);
                    this.debug && console.log('token fits:',token);
                }
            })
            return res;
        } else {
            return decodedTokens;
        }
    }

    compareObjects(o1, o2){
        for(var p in o1){
            if(o1.hasOwnProperty(p)){
                if(o1[p].toString() !== o2[p].toString()){
                    return false;
                }
            }
        }
        for(var p in o2){
            if(o2.hasOwnProperty(p)){
                if(o1[p].toString() !== o2[p].toString()){
                    return false;
                }
            }
        }
        return true;
    };

    // read tokens from local storage and return as object {tokens: [], noTokens: boolean, success: boolean}
    readTokens(){
        const storageTickets = localStorage.getItem(this.localStorageItemName);
        let tokens = [];
        let output = {tokens: [], noTokens: true, success: true};
        try {
            if (storageTickets && storageTickets.length) {
                // Build new list of tickets from current and query ticket { ticket, secret }
                tokens = JSON.parse(storageTickets);
                if (tokens.length !== 0) {

                    // output.tokens = tokens;
                    tokens.forEach(item => {
                        if (item.token && item.secret) {
                            output.tokens.push({
                                token: item.token,
                                secret: item.secret
                            })
                        }
                    })
                }
                if (output.tokens.length) {
                    output.noTokens = false;
                }
            }
        } catch (e) {
            console.log('Cant parse tokens in LocalStorage');
            if (typeof callBack === "function") {
                output.success = false;
            }
        }
        return output;
    }

    getRawToken(unsignedToken){
        let tokensOutput = this.readTokens();
        if (tokensOutput.success && !tokensOutput.noTokens) {
            let rawTokens = tokensOutput.tokens;

            let token = false;

            if (rawTokens.length) {
                rawTokens.forEach(tokenData=> {
                    if (tokenData.token){
                        let decodedToken = new this.tokenParser(this.base64ToUint8array(tokenData.token).buffer);
                        if (decodedToken && decodedToken[this.unsignedTokenDataName]) {
                            let decodedTokenData = decodedToken[this.unsignedTokenDataName];

                            if (this.compareObjects(decodedTokenData, unsignedToken)){
                                token = tokenData;
                            }

                        }
                    } else {
                        console.log('empty token data received');
                    }

                })
            }

            return token;
        }
    }

    listenForIframeMessages(event){

        let tokensOriginURL = new URL(this.tokensOrigin);

        // listen only tokensOriginURL
        if (event.origin !== tokensOriginURL.origin) {
            return;
        }

        // console.log('parent: event = ', event.data);

        // iframeCommand required for interaction
        if (
            typeof event.data.iframeCommand === "undefined"
            || typeof event.data.iframeData === "undefined"
        ) {
            return;
        }

        // iframeCommand contain command code

        let command = event.data.iframeCommand;

        // iframeData contains command content (tokens data, useToken , hide/display iframe)
        let data = event.data.iframeData;

        console.log('parent: command, data = ', command, data);

        switch (command) {
            case "iframeWrap":
                if (data == "show") {
                    this.tokenIframeWrap.style.display = 'block';
                } else if (data == "hide"){
                    this.tokenIframeWrap.style.display = 'none';
                }
                break;
            case "tokensData":
                // tokens received, disable listener
                this.detachPostMessageListener(this.listenForIframeMessages);
                // TODO remove iframeWraper
                this.tokenIframeWrap.remove();

                if (data.success && !data.noTokens) {
                    data.tokens = this.filterTokens(data.tokens);
                }
                this.negotiateCallback(data);
                break;

            case "useTokenData":

                this.tokenIframeWrap.remove();

                // if (data.success) {
                //     console.log('useTokenData: ' + data.useToken)
                // } else {
                //     console.log('useTokenData error message: ' + data.message)
                // }
                console.log('this.signCallback(data)');
                this.signCallback && this.signCallback(data);
                this.signCallback = false;
                break;

            case "iframeReady":
                event.source.postMessage(this.queuedCommand, event.origin);
                this.queuedCommand = '';
                break;

            default:

        }


    }

    signToken(unsignedToken, signCallback){
        this.signCallback = signCallback;
        // open iframe and request tokens
        this.queuedCommand = {parentCommand: 'signToken',parentData: unsignedToken};
        this.createIframe();
    }

    negotiate(callBack) {
        // callback function required
        if (typeof callBack !== "function") {
            return false;
        }

        console.log('negotiateCallback added;');

        this.negotiateCallback = callBack;

        console.log('attestationOrigin = '+this.attestationOrigin);
        if (this.attestationOrigin) {

            if (window.location.href === this.tokensOrigin) {
                // just read an return tokens
                let tokensOutput = this.readTokens();
                if (tokensOutput.success && !tokensOutput.noTokens) {
                    let decodedTokens = this.decodeTokens(tokensOutput.tokens);
                    let filteredTokens = this.filterTokens(decodedTokens);
                    tokensOutput.tokens = filteredTokens;
                    this.negotiateCallback(tokensOutput);
                }
            } else {
                this.queuedCommand = {parentCommand: 'tokensList',parentData: ''};
                this.createIframe()
            }
        } else {
            console.log('no attestationOrigin...');
            // TODO test token against blockchain and show tokens as usual view
        }
    }

    createIframe(){
        console.log('open iframe');
        // open iframe and request tokens
        this.attachPostMessageListener(this.listenForIframeMessages.bind(this));

        const iframe = document.createElement('iframe');
        this.iframe = iframe;
        iframe.src = this.tokensOrigin;
        iframe.style.width = '800px';
        iframe.style.height = '700px';
        iframe.style.maxWidth = '100%';
        iframe.style.background = '#fff';
        let iframeWrap = document.createElement('div');
        this.tokenIframeWrap = iframeWrap;
        iframeWrap.setAttribute('style', 'width:100%; min-height: 100vh; position: fixed; align-items: center; justify-content: center; display: none; top: 0; left: 0; background: #fffa');
        iframeWrap.appendChild(iframe);
        document.body.appendChild(iframeWrap);
    }

    base64ToUint8array( base64str ) {
        // decode base64url to base64. it will do nothing for base64
        base64str = base64str.split('-').join('+')
            .split('_').join('/')
            .split('.').join('=');
        let res;

        if (typeof Buffer !== 'undefined') {
            res = Uint8Array.from(Buffer.from(base64str, 'base64'));
        } else {
            res = Uint8Array.from(atob(base64str), c => c.charCodeAt(0));
        }
        return res;
    }

    decodeTokens(rawTokens){
        if (this.debug) {
            console.log('decodeTokens fired');
            console.log(rawTokens);
        }
        let decodedTokens = [];
        if (rawTokens.length) {
            rawTokens.forEach(tokenData=> {
                if (tokenData.token){
                    let decodedToken = new this.tokenParser(this.base64ToUint8array(tokenData.token).buffer);
                    if (decodedToken && decodedToken[this.unsignedTokenDataName]) decodedTokens.push(decodedToken[this.unsignedTokenDataName]);
                } else {
                    console.log('empty token data received');
                }

            })
        }
        return decodedTokens;
    }

    attachPostMessageListener(listener){
        if (window.addEventListener) {
            window.addEventListener("message", listener, false);
        } else {
            // IE8
            window.attachEvent("onmessage", listener);
        }
    }
    detachPostMessageListener(listener){
        if (window.addEventListener) {
            window.removeEventListener("message", listener, false);
        } else {
            // IE8
            window.detachEvent("onmessage", listener);
        }
    }
}
