import {SignedDevconTicket} from "../asn1/shemas/SignedDevconTicket";

export const XMLconfigData = {
    attestationOrigin: "http://stage.attestation.id",
    tokensOrigin: "https://devcontickets.herokuapp.com/outlet/",
    tokenUrlName: 'ticket',
    tokenSecretName: 'secret',
    unsignedTokenDataName: 'ticket',
    // tokenParserUrl: '',
    tokenParser: SignedDevconTicket,
    localStorageItemName: 'dcTokens',
    // base64senderPublicKey: '04950C7C0BED23C3CAC5CC31BBB9AAD9BB5532387882670AC2B1CDF0799AB0EBC764C267F704E8FDDA0796AB8397A4D2101024D24C4EFFF695B3A417F2ED0E48CD',
    base64senderPublicKey: '-----BEGIN PUBLIC KEY-----\n' +
        'MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA////////////////\n' +
        '/////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' +
        'AAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5m\n' +
        'fvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0\n' +
        'SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQNkFB\n' +
        'AgEBA0IABJUMfAvtI8PKxcwxu7mq2btVMjh4gmcKwrHN8HmasOvHZMJn9wTo/doH\n' +
        'lquDl6TSEBAk0kxO//aVs6QX8u0OSM0=\n' +
        '-----END PUBLIC KEY-----',

    base64attestorPubKey:
    // stage.attestation.id public key
        "MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////////////////////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQNkFBAgEBA0IABL+y43T1OJFScEep69/yTqpqnV/jzONz9Sp4TEHyAJ7IPN9+GHweCX1hT4OFxt152sBN3jJc1s0Ymzd8pNGZNoQ=",
    webDomain: 'devcon.org'
};
