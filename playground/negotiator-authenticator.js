// import Negotiator()
// import Authenticator()

const negotiatorAuthenticator = {};
const currentUser = 2;

// Helper for success and failed promises
const asyncHelper = async (promise) => {
    try {
        const data = await promise;
        return [data, undefined];
    } catch (error) {
        return [undefined, error];
    }
}

// Mock of Negotiator
const Negotiator = {
    getTokenInstances: function async() {
        return [
            { id: 42, token: { ticketClass: "VIP" }, ownerAddress: null },
            { id: 32, token: { ticketClass: "STANDARD" }, ownerAddress: 2 },
            { id: 15, token: { ticketClass: "VIP" }, ownerAddress: 2 },
        ];
    }
};

// Mock of Authenticator
const Authenticator = {
    authenticateAddress: async function () {
        return true;
    },
    findOwner: async function () {
        return 2
    },
    authenticate: async function () {
        return "Authenticated"
    }
};

// to provide the VIP Status and Tokens
negotiatorAuthenticator.init = async () => {
    // 1. Get most up to date Tokens
    const [tokens, tokensErr] = await asyncHelper(Negotiator.getTokenInstances());
    if (tokensErr) return negotiatorAuthenticator.errorHandler("Could not resolve token instances");
    // 2. Determine if the user has VIP tokens (for front end developers UI / UX)
    let isVIP = false;
    tokens.map(ticket => { if (ticket.token.ticketClass == "VIP") isVIP = true });
    if (isVIP) document.getElementById("vip-only-section").style.display = "block";
    // 3. Return the and tokens
    return tokens;
}

// to handle the vip click event from the end user
negotiatorAuthenticator.vipClickEvent = async () => {
    // 1. Get most up to date Tokens (Confirm if this should be done)
    const [tokens, tokensErr] = await asyncHelper(Negotiator.getTokenInstances());
    if (tokensErr) return negotiatorAuthenticator.errorHandler("Could not resolve token instances");
    // 2. Gather all VIP tickets
    const vipTickets = tokens.filter(ticket => (ticket.token.ticketClass == "VIP"));
    // 3. Build a Html template of tickets to show inside Modal
    let ticketsToHtml = "<p>Your VIP Tickets</p>";
    vipTickets.map(function (ticket) { ticketsToHtml += `<button style="margin: 20px" data-id="${ticket.id}" onClick="negotiatorAuthenticator.selectVipTicket(${ticket.id})">${ticket.id}</button>`; });
    // 4. Render the tickets inside the Modal
    document.getElementById("modal-inner-content").innerHTML = ticketsToHtml;
    // 5. Show Modal
    document.getElementById("modal").style.display = 'block';
}

// to handle the vip selection click event from the end user
negotiatorAuthenticator.selectVipTicket = async (ticketId) => {
    event.stopPropagation();
    // 1. Get most up to date Tokens (Confirm if this should be done each time)
    const [tokens, tokensErr] = await asyncHelper(Negotiator.getTokenInstances());
    if (tokensErr) return negotiatorAuthenticator.errorHandler("Could not resolve token instances");
    // 2. Get the ticket using ID
    const chosenTicket = tokens.filter(ticket => (ticket.id == ticketId))[0];
    // 3. Authenticator (non-Disney mode)
    // to confirm with Weiwu - the following steps: do I create this modal within an Authenticator module?
    if (chosenTicket.ownerAddress == null) {
        // lead to email code modal process, created by Authenticator.
        Authenticator.findOwner();
    }
    if (chosenTicket.ownerAddress == currentUser.ownerAddress) {
        // this will lead to sign-message, even if user typed the code in email.
        Authenticator.authenticateAddress(currentUser.ownerAddress).then(function (result) {
            console.log(result);
        }, function (error) {
            console.log(error);
        });
    }
    // 4. Authenticate ticket
    Authenticator.authenticate(chosenTicket).then(function (result) {
        console.log(result);
    }, function (error) {
        console.log(error);
    });
    // Demo only - Show the selected ticket id.
    alert("Card Selected: " + chosenTicket.id);
}

negotiatorAuthenticator.errorHandler = (msg) => {
    return { error: msg }
};

function closeModal() {
    document.getElementById("modal").style.display = 'none';
}

// onload :
// async function() {
//     const tokens = (await Negotiator.getXXXTokenInstances());
//     tokens.forEach(putTokenOnUI);

//     // getting the attributes of tokens

//     isVIP = false;
//     tokens.forEach(
//         ticket => {
//             if (token.ticketClass == "VIP") isVIP = true;
//         }
//     }

//     // isVIP == the user has at least one token which is VIP.

//     document.getElementByID("vip-only-section").style.visibility = "visible";
// }()

// // when user clicked "VIP room" button

// async function vip-room-clicked() {

//     /// ... let user choose which ticket to use for authentication
//     vip-tickets = tokens.filter( ticket => (ticket.ticketClass== "VIP") );

//     // populate the vip-ticket selector window
//     populate-vip-ticket(vip-tickets).then(chosenTicket => {
//         // first approach: disney mode
//         // this will lead to sign-message or email code
//         Authenticator.authenticate(chosenTicket).then(success, failure);
//     });

//     // non-disney mode
//     populate-vip-ticket(vip-tickets).then(chosenTicket => {
//         if (chosenTicket.ownerAddress == null ) {
//             Authenticator.findOwner() // lead to email code modal process, created by Authenticator.
//         }
//         if (chosenTicket.ownerAddress == currentUser.ownerAddress) {
//             // this will lead to sign-message, even if user typed the code in email.
//             Authenticator.authenticateAddress(currentUser.ownerAddress).then(success, failure);
//         }
//     });
// }

// // if the website generates a transaction to a smart contract which
// // requires a valid ticket.

// async function voteButtonCicked(ticket) {
//     // generate the vote transaction payloads (e.g. whom voted)
//     const payload = {vote: votedGui, weight: 3, expiry: 98109802843804}
//     payload.push(Authenticator.getProofOf(ticket))
//     // now it is {vote: votedGui, weight: 3, expiry: 98109802843804, ticketProof: proof}
//     // where the genreation of the proof might involve receiving email code in modal.
//     tx = {nounce: nounce, ......, payload: payload}
//     web3.ethereum.sendTransaction(tx); // then track the transaction status ...
// }

// // card at work: this will use wallet if possible, and this only works
// // if the vote action is provided (by the issuer)
// async function voteButtonClick() {
//     ticket.actions["vote"].render(document.querySelector(".voteCardContainer")).then(tx => watch(tx));
// }