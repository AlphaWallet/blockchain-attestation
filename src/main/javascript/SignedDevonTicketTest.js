
import { fromBER } from "asn1js";
import SignedDevconTicket from "./SignedDevonTicket.js"
import { readFileSync } from 'fs';

const der = readFileSync('build/test-results/signed-devcon-ticket.der')
const ans1 = fromBER(new Uint8Array(der).buffer);
const ticket = new SignedDevconTicket({
    schema: ans1.result,
});
const { devconId, ticketClass, ticketId, riddle } = ticket;
const text = `devconId = ${devconId}, ticketId = ${ticketId}, ticketClass = ${ticketClass}, riddle = ${riddle}`;

console.log(text);

