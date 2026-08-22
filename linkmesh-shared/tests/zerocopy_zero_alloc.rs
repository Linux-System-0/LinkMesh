// LinkMesh - 可以在多个操作系统上运行的内网穿透工具
// Copyright (C) 2026 Linux-System-0(Github) / 一架在Linux上起飞的A320(Bilibili) <ls0_1@qq.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! 零拷贝（zero-copy）严格验证（独立二进制，避免并行测试污染分配计数）：
//! 数据面发送热路径 `encrypt_with_nonce_into` 在复用缓冲上就地加密时**零堆分配**。

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use linkmesh_shared::crypto::{self, RawKey};

/// 计数分配器：统计堆分配次数。
struct CountingAllocator;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::SeqCst);
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::SeqCst);
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::SeqCst);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

#[test]
fn inplace_encrypt_hot_path_allocates_zero() {
    let key: RawKey = [0x11; 32];
    let nonce = crypto::session_nonce(7, 0);
    let payload = [0xABu8; 512];
    // 预分配复用缓冲（该次分配在计数之前，不计入断言）
    let mut buf: Vec<u8> = Vec::with_capacity(2048);

    // 清零计数，然后只跑就地加密热路径
    ALLOCS.store(0, Ordering::SeqCst);
    let start = ALLOCS.load(Ordering::SeqCst);
    for _ in 0..1000 {
        crypto::encrypt_with_nonce_into(&key, &nonce, &payload, &mut buf);
    }
    let end = ALLOCS.load(Ordering::SeqCst);

    assert_eq!(
        end - start,
        0,
        "encrypt_with_nonce_into 数据面热路径必须零分配（zero-copy），实际 {} 次",
        end - start
    );

    // 输出与分配版逐字节一致（线上格式兼容）
    let expected = crypto::encrypt_with_nonce(&key, &nonce, &payload);
    assert_eq!(buf, expected);
}
