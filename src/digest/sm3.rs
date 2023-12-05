// todo copyright

// Copyright 2018 Cryptape Technology LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//
// Sample 1
// Input:"abc"
// Output:66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0

// Sample 2
// Input:"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
// Outpuf:debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732

use crate::c;
use core::num::Wrapping;

#[inline(always)]
fn ff0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn ff1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

#[inline(always)]
fn gg0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn gg1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[inline(always)]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

#[inline(always)]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

#[inline(always)]
fn get_u32_be(b: &[u8; 64], i: usize) -> u32 {
    u32::from(b[i]) << 24
        | u32::from(b[i + 1]) << 16
        | u32::from(b[i + 2]) << 8
        | u32::from(b[i + 3])
}

pub(super) extern "C" fn sm3_block_data_order(
    state: &mut super::State,
    data: *const u8,
    num: c::size_t,
) {
    let state = unsafe { &mut state.as32 };
    *state = block_data_order(*state, data, num)
}

fn block_data_order(mut H: [Wrapping<u32>; 8], M: *const u8, num: c::size_t) -> [Wrapping<u32>; 8] {
    let M = M as *const [u8; 64];
    let M: &[[u8; 64]] = unsafe { core::slice::from_raw_parts(M, num) };

    for M in M {
        //get expend
        let mut w: [u32; 68] = [0; 68];
        let mut w1: [u32; 64] = [0; 64];

        let mut i = 0;
        while i < 16 {
            w[i] = get_u32_be(&M, i * 4);

            i += 1;
        }

        i = 16;
        while i < 68 {
            w[i] = p1(w[i - 16] ^ w[i - 9] ^ w[i - 3].rotate_left(15))
                ^ w[i - 13].rotate_left(7)
                ^ w[i - 6];

            i += 1;
        }

        i = 0;
        while i < 64 {
            w1[i] = w[i] ^ w[i + 4];

            i += 1;
        }

        let mut ra = H[0].0;
        let mut rb = H[1].0;
        let mut rc = H[2].0;
        let mut rd = H[3].0;
        let mut re = H[4].0;
        let mut rf = H[5].0;
        let mut rg = H[6].0;
        let mut rh = H[7].0;
        let mut ss1: u32;
        let mut ss2: u32;
        let mut tt1: u32;
        let mut tt2: u32;

        i = 0;
        while i < 16 {
            ss1 = ra
                .rotate_left(12)
                .wrapping_add(re)
                .wrapping_add(0x79cc_4519u32.rotate_left(i as u32))
                .rotate_left(7);
            ss2 = ss1 ^ ra.rotate_left(12);
            tt1 = ff0(ra, rb, rc)
                .wrapping_add(rd)
                .wrapping_add(ss2)
                .wrapping_add(w1[i]);
            tt2 = gg0(re, rf, rg)
                .wrapping_add(rh)
                .wrapping_add(ss1)
                .wrapping_add(w[i]);
            rd = rc;
            rc = rb.rotate_left(9);
            rb = ra;
            ra = tt1;
            rh = rg;
            rg = rf.rotate_left(19);
            rf = re;
            re = p0(tt2);

            i += 1;
        }

        i = 16;
        while i < 64 {
            ss1 = ra
                .rotate_left(12)
                .wrapping_add(re)
                .wrapping_add(0x7a87_9d8au32.rotate_left(i as u32))
                .rotate_left(7);
            ss2 = ss1 ^ ra.rotate_left(12);
            tt1 = ff1(ra, rb, rc)
                .wrapping_add(rd)
                .wrapping_add(ss2)
                .wrapping_add(w1[i]);
            tt2 = gg1(re, rf, rg)
                .wrapping_add(rh)
                .wrapping_add(ss1)
                .wrapping_add(w[i]);
            rd = rc;
            rc = rb.rotate_left(9);
            rb = ra;
            ra = tt1;
            rh = rg;
            rg = rf.rotate_left(19);
            rf = re;
            re = p0(tt2);

            i += 1;
        }

        H[0].0 ^= ra;
        H[1].0 ^= rb;
        H[2].0 ^= rc;
        H[3].0 ^= rd;
        H[4].0 ^= re;
        H[5].0 ^= rf;
        H[6].0 ^= rg;
        H[7].0 ^= rh;
    }

    H
}
