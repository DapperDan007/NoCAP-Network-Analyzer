import { writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

function checksum(buffer) {
  let sum=0; for(let i=0;i<buffer.length;i+=2)sum+=(buffer[i]<<8)+(buffer[i+1]||0);
  while(sum>>>16)sum=(sum&65535)+(sum>>>16);return (~sum)&65535;
}
function packet(src,dst,protocol,payload) {
  const eth=Buffer.from('001122334455aabbccddeeff0800','hex');
  const ip=Buffer.alloc(20);ip[0]=0x45;ip.writeUInt16BE(20+payload.length,2);ip[8]=64;ip[9]=protocol;
  Buffer.from(src.split('.').map(Number)).copy(ip,12);Buffer.from(dst.split('.').map(Number)).copy(ip,16);ip.writeUInt16BE(checksum(ip),10);
  return Buffer.concat([eth,ip,payload]);
}
function syn(src,dst,sport,dport){
  const tcp=Buffer.alloc(20);tcp.writeUInt16BE(sport);tcp.writeUInt16BE(dport,2);tcp.writeUInt32BE(sport,4);tcp[12]=0x50;tcp[13]=2;tcp.writeUInt16BE(65535,14);
  const pseudo=Buffer.alloc(12);Buffer.from(src.split('.').map(Number)).copy(pseudo);Buffer.from(dst.split('.').map(Number)).copy(pseudo,4);pseudo[9]=6;pseudo.writeUInt16BE(tcp.length,10);tcp.writeUInt16BE(checksum(Buffer.concat([pseudo,tcp])),16);
  return packet(src,dst,6,tcp);
}
function dns(name){
  const header=Buffer.alloc(12);header.writeUInt16BE(123,0);header.writeUInt16BE(0x0100,2);header.writeUInt16BE(1,4);
  const query=Buffer.concat([...name.split('.').map(label=>Buffer.concat([Buffer.from([label.length]),Buffer.from(label)])),Buffer.from([0,0,1,0,1])]);
  const payload=Buffer.concat([header,query]);const udp=Buffer.alloc(8);udp.writeUInt16BE(53000);udp.writeUInt16BE(53,2);udp.writeUInt16BE(8+payload.length,4);
  return packet('192.168.1.20','192.168.1.1',17,Buffer.concat([udp,payload]));
}
export function fixture(){
  const global=Buffer.alloc(24);global.writeUInt32LE(0xa1b2c3d4);global.writeUInt16LE(2,4);global.writeUInt16LE(4,6);global.writeUInt32LE(65535,16);global.writeUInt32LE(1,20);
  const packets=[{time:0,data:dns('telemetry.example.test')}];
  for(let i=0;i<22;i++)packets.push({time:i+1,data:syn('192.168.1.20','93.184.216.34',40000+i,1000+i)});
  for(let i=0;i<8;i++)packets.push({time:30+i*10,data:syn('192.168.1.30','93.184.216.34',50000+i,443)});
  return Buffer.concat([global,...packets.flatMap(({time,data})=>{const h=Buffer.alloc(16);h.writeUInt32LE(1700000000+time);h.writeUInt32LE(data.length,8);h.writeUInt32LE(data.length,12);return [h,data];})]);
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href){const target=process.argv[2]||'sample.pcap';await writeFile(target,fixture());console.log(`Wrote ${target}: 31 synthetic packets. No real user traffic.`);}
