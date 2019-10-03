use std::env;
extern crate failure;
use linked_list::LinkedList;

use std::fs::File;
use std::io::prelude::*;

use std::io;
use std::io::SeekFrom;

use chrono::{NaiveDateTime, NaiveTime};

const QUOTE_SIZE: usize = 210;

#[derive(Debug)]
//The Global header
pub struct Header {
    thiszone: u32, // timestamp second offset
    snaplen: u32,  // size of data
}

#[derive(Debug)]
//The PCAP Packet header
struct PacketHeader {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
}

//For the case when the packet needs to be skipped
type SkipPacketHeader = i64;

#[derive(Debug, Clone)]
//Contains the price + quantity data
//these are converted into u32 so that the padding 0's are taken out
//(there is an easy fix if it was preferred to have those padding 0's)
struct QuoteData {
    price: u32,
    quantity: u32,
}
impl QuoteData {
    fn new(i: usize, buf: &[u8; QUOTE_SIZE]) -> QuoteData {
        QuoteData {
            price: (buf[i + 0] - 48) as u32 * 10_000
                + (buf[i + 1] - 48) as u32 * 1_000
                + (buf[i + 2] - 48) as u32 * 100
                + (buf[i + 3] - 48) as u32 * 10
                + (buf[i + 4] - 48) as u32,
            quantity: (buf[i + 5] - 48) as u32 * 1_000_000
                + (buf[i + 6] - 48) as u32 * 100_000
                + (buf[i + 7] - 48) as u32 * 10_000
                + (buf[i + 8] - 48) as u32 * 1_000
                + (buf[i + 9] - 48) as u32 * 100
                + (buf[i + 10] - 48) as u32 * 10
                + (buf[i + 11] - 48) as u32,
        }
    }
    fn print(&self, out: &mut std::io::Stdout) -> io::Result<()> {
        out.write(format!(" {}@{}", self.quantity, self.price).as_bytes())?;
        Ok(())
    }
}
//Function for only printing the packets as they come in, with no reordering
fn only_print(
    _list: &mut LinkedList<QuotePacket>,
    pkt: QuotePacket,
    out: &mut std::io::Stdout,
) -> io::Result<()> {
    pkt.print(out)?;
    Ok(())
}
//Reorders the packets based on the accept time, using a linked list
fn print_and_reorder(
    list: &mut LinkedList<QuotePacket>,
    pkt: QuotePacket,
    out: &mut std::io::Stdout,
) -> io::Result<()> {
    if list.is_empty() {
        list.push_front(pkt);
        return Ok(());
    } else {
        if (list.front().unwrap().pkt_sec % 3600) * 1000 + list.front().unwrap().pkt_usec
            < (pkt.pkt_sec % 3600) * 1000 + pkt.pkt_usec - 3000u32
        {
            list.pop_front().unwrap().print(out)?;
            if list.is_empty() {
                list.push_front(pkt);
                return Ok(());
            } else {
                return print_and_reorder(list, pkt, out);
            }
        } else {
            list.insert(find_spot(0, list.iter(), &pkt), pkt);
            return Ok(());
        }
    }
}
fn find_spot(
    index: usize,
    mut iter: linked_list::Iter<QuotePacket>,
    packet: &QuotePacket,
) -> usize {
    let next = iter.next();
    if next.is_none() {
        return index;
    } else {
        let next_real = next.unwrap();
        if next_real.accept_time < packet.accept_time {
            return find_spot(index + 1, iter, packet);
        } else {
            if next_real.pkt_usec < packet.pkt_usec {
                return find_spot(index + 1, iter, packet);
            } else {
                return index;
            }
        }
    }
}

/*
Issue code	12 Issue seq.-no. 3
Market Status Type	2
Total bid quote volume	7
Best bid price(1st..5th)5  Best bid quantity(1st..5th) 7
Total ask quote volume	7
Best ask price(1st..5th)  	5  Best ask quantity(1st..5th)	7
No. of best bid valid quote(total)	5
No. of best bid quote(1st..5th)	4
No. of best ask valid quote(total)	5
No. of best ask quote(1st..5th)	4
Quote accept time	8	HHMMSSuu
*/
#[derive(Debug, Clone)]
struct QuotePacket {
    pkt_sec: u32,
    pkt_usec: u32,
    accept_time: i32,
    accept_time_h: u8,
    accept_time_m: u8,
    accept_time_s: u8,
    accept_time_u: u8,
    issue_code: [u8; 12],
    bids: [QuoteData; 5],
    asks: [QuoteData; 5],
}
impl QuotePacket {
    fn new(header: &PacketHeader, buf: &[u8; QUOTE_SIZE]) -> QuotePacket {
        let accept_time_h = (buf[QUOTE_SIZE - 9] - 48) * 10 + buf[QUOTE_SIZE - 8] - 48;
        let accept_time_m = (buf[QUOTE_SIZE - 7] - 48) * 10 + buf[QUOTE_SIZE - 6] - 48;
        let accept_time_s = (buf[QUOTE_SIZE - 5] - 48) * 10 + buf[QUOTE_SIZE - 4] - 48;
        let accept_time_u = (buf[QUOTE_SIZE - 3] - 48) * 10 + buf[QUOTE_SIZE - 2] - 48;

        let issue_code = [
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            buf[10], buf[11],
        ];
        const BID_START: usize = 24usize;
        let bids = [
            QuoteData::new(BID_START + 12 * 4, buf),
            QuoteData::new(BID_START + 12 * 3, buf),
            QuoteData::new(BID_START + 12 * 2, buf),
            QuoteData::new(BID_START + 12 * 1, buf),
            QuoteData::new(BID_START + 12 * 0, buf),
        ];
        const ASK_START: usize = BID_START + 12 * 5 + 7;
        let asks = [
            QuoteData::new(ASK_START, buf),
            QuoteData::new(ASK_START + 12, buf),
            QuoteData::new(ASK_START + 12 * 2, buf),
            QuoteData::new(ASK_START + 12 * 3, buf),
            QuoteData::new(ASK_START + 12 * 4, buf),
        ];

        QuotePacket {
            pkt_sec: header.ts_sec,
            pkt_usec: header.ts_usec,
            accept_time: (accept_time_h as i32) * 60 * 60 * 100
                + (accept_time_m as i32) * 60 * 100
                + (accept_time_s as i32) * 100
                + accept_time_u as i32,
            accept_time_h: accept_time_h,
            accept_time_m: accept_time_m,
            accept_time_s: accept_time_s,
            accept_time_u: accept_time_u,
            issue_code: issue_code,
            bids: bids,
            asks: asks,
        }
    }
    //<pkt-time> <accept-time> <issue-code> <bqty5>@<bprice5> ... <bqty1>@<bprice1> <aqty1>@<aprice1> ... <aqty5>@<aprice5>
    fn print(&self, out: &mut std::io::Stdout) -> io::Result<()> {
        out.write(
            format!(
                "{} {} ",
                NaiveDateTime::from_timestamp(self.pkt_sec as i64, self.pkt_usec * 1_000,),
                NaiveTime::from_hms_milli(
                    self.accept_time_h as u32,
                    self.accept_time_m as u32,
                    self.accept_time_s as u32,
                    (self.accept_time_u as u32) * 10
                )
            )
            .as_bytes(),
        )?;
        out.write(&self.issue_code)?;
        for bid in self.bids.iter() {
            bid.print(out)?;
        }
        for ask in self.asks.iter() {
            ask.print(out)?;
        }
        out.write(&['\n' as u8])?;
        Ok(())
    }
}

//Takes the Packet header(16 bytes) and the UDP Port nubmer(2 bytes) and the Quote data header (5 bytes)
//After this function is called 62 bytes from the headers will have been read or skipped
//Parses out a PacketHeader iff:
//  incl_len and orig_len from the Packet header are equal, as partial data packets are not supported
//
fn packet_header(
    ph_buf: &mut [u8],
    port_buf: &mut [u8],
    qdh_buf: &mut [u8],
) -> Result<PacketHeader, SkipPacketHeader> {
    let incl_len = read_u32(ph_buf[8], ph_buf[9], ph_buf[10], ph_buf[11]);
    let orig_len = read_u32(ph_buf[12], ph_buf[13], ph_buf[14], ph_buf[15]);
    if incl_len != orig_len || incl_len != QUOTE_SIZE as u32 + 47 {
        Err(incl_len as i64 - 47)
    } else {
        //Checks the destination port
        //52 = byte 36 after the initial packet_header or 16
        //53 = byte 37 after the initial packet_header or 16
        //60 is the big part of the port number of either 15515 or 15516
        //155 is the small part of the port number 15515
        //156 is the small part of the port number 15516
        if port_buf[0] != 60 || (port_buf[1] != 155 && port_buf[1] != 156) {
            return Err(incl_len as i64 - 47);
        }
        //Checks the quote data header
        //0-1 = 'B' '6'
        //2-3 = '0' '3'
        //4   = '4'
        if qdh_buf[0] != 66
            || qdh_buf[1] != 54
            || qdh_buf[2] != 48
            || qdh_buf[3] != 51
            || qdh_buf[4] != 52
        {
            return Err(incl_len as i64 - 47);
        }
        Ok(PacketHeader {
            ts_sec: read_u32(ph_buf[0], ph_buf[1], ph_buf[2], ph_buf[3]),
            ts_usec: read_u32(ph_buf[4], ph_buf[5], ph_buf[6], ph_buf[7]),
            incl_len: incl_len,
            orig_len: orig_len,
        })
    }
}

//Prints all the quotes
fn print_quote(
    f: &mut File,
    write_to_out: &dyn Fn(
        &mut LinkedList<QuotePacket>,
        QuotePacket,
        &mut std::io::Stdout,
    ) -> io::Result<()>,
) -> Result<(), failure::Error> {
    let mut b32 = [0u8; 4];
    let thiszone = skip_and_read_32(f, 8i64, &mut b32)?; //skip 8+read 4; current = 12
    let snaplen = skip_and_read_32(f, 4i64, &mut b32)?; //skip 4+read 4; crruent 20
    let _header = Header {
        thiszone: thiszone,
        snaplen: snaplen,
    };
    if f.seek(SeekFrom::Current(4))? == 0 {
        //skip 4; current 24
        return Err(failure::err_msg("Failed to fully read a chunk! E[003]"));
    }
    let mut ph_buf = [0u8; 16];
    let mut port_buf = [0u8; 2];
    let mut qdh_buf = [0u8; 5];
    let mut out = std::io::stdout();
    let mut list: LinkedList<QuotePacket> = LinkedList::new();
    for _ in 0..snaplen {
        //Read the packet header
        if f.read(&mut ph_buf)? == 0 {
            //if no packet header is read, then we are at the end of the file
            break;
        };
        //skip 36 to the port udp address
        f.seek(SeekFrom::Current(36))?;
        //Read the UDP header for the port
        f.read(&mut port_buf)?;
        //skip ahead to the quote data header
        f.seek(SeekFrom::Current(4))?;
        //read the Quote packet's header data, to ensure it has B6034
        f.read(&mut qdh_buf)?;
        match packet_header(&mut ph_buf, &mut port_buf, &mut qdh_buf) {
            Ok(packet_header) => {
                //let quote_length = packet_header.incl_len as u64 - 47u64;
                //read the quote into a buffer
                let mut q_buf = [0u8; QUOTE_SIZE];
                f.read(&mut q_buf)?;
                //parse quote into packet
                let qp = QuotePacket::new(&packet_header, &q_buf);
                //write out the quote packet
                write_to_out(&mut list, qp, &mut out)?;
            }
            Err(skip_header) => {
                f.seek(SeekFrom::Current(skip_header))?;
            }
        }
    }
    for pkt in list {
        pkt.print(&mut out)?;
    }
    out.flush()?;
    Ok(())
}

fn main() -> Result<(), failure::Error> {
    let mut args = env::args();
    if let Some(_) = args.next() {
        // skip the first arg
        if let Some(file_name) = args.next() {
            match File::open(file_name) {
                Ok(mut file) => print_quote(
                    &mut file,
                    match args.next() {
                        Some(flag) => {
                            if flag == "-r" {
                                &print_and_reorder
                            } else {
                                &only_print
                            }
                        }
                        None => &only_print,
                    },
                )?,
                Err(err) => return Err(err.into()),
            }
        } else {
            return Err(failure::err_msg(format!("No resource provided!")));
        }
    }

    // and more! See the other methods for more details.
    Ok(())
}

//Skips the next X bytes, then reads Y bytes into a splice [u8,Y]
fn skip_and_read_32(f: &mut File, skip_to: i64, mut b32: &mut [u8]) -> Result<u32, failure::Error> {
    let size = f.seek(SeekFrom::Current(skip_to))?;
    if size == 0 {
        return Err(failure::err_msg("Failed to fully read a chunk! E[001]"));
    }
    let size = f.read(&mut b32)?;
    if size == 0 {
        return Err(failure::err_msg("Failed to fully read a chunk! E[002]"));
    }

    Ok(read_u32(b32[0], b32[1], b32[2], b32[3]))
}

//Reads in 4 bytes in little endian and outputs a u32
fn read_u32(u4: u8, u3: u8, u2: u8, u1: u8) -> u32 {
    (u1 as u32 * 16777216) + (u2 as u32 * 65536) + (u3 as u32 * 256) + (u4 as u32)
}
