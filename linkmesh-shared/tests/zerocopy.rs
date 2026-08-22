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

//! 零拷贝（zero-copy）验证：对比「分配版」与「就地版」的差异，并验证输出逐字节一致。
//!
//! 注意：严格「零分配」断言见独立二进制 `zerocopy_zero_alloc.rs`（本文件含多个会分配
//! 的测试，并行执行会污染全局分配计数）。

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use linkmesh_shared::crypto::{self, RawKey};

/// 计数分配器：统计堆分配次数（非零、非释放）。
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

/// 三个计数测试共享全局分配器，必须串行执行（并行会互相污染计数）。
static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn allocs_snapshot() -> usize {
    ALLOCS.load(Ordering::SeqCst)
}

#[test]
fn allocating_variant_allocates_per_call() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let key: RawKey = [0x22; 32];
    let nonce = crypto::session_nonce(8, 0);
    let payload = [0xCDu8; 512];

    ALLOCS.store(0, Ordering::SeqCst);
    let start = allocs_snapshot();
    for _ in 0..100 {
        crypto::encrypt_with_nonce(&key, &nonce, &payload);
    }
    let end = allocs_snapshot();

    // 分配版每调用至少分配一次（证明计数分配器有效，也凸显就地版收益）
    assert!(
        end - start >= 100,
        "encrypt_with_nonce（分配版）每调用应至少 1 次分配，实际 {} 次",
        end - start
    );
}

#[test]
fn inplace_output_byte_identical_to_allocating() {
    let key: RawKey = [0x33; 32];
    let nonce = crypto::session_nonce(9, 0);
    let payload = [0xE1u8; 300];
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    crypto::encrypt_with_nonce_into(&key, &nonce, &payload, &mut buf);
    let expected = crypto::encrypt_with_nonce(&key, &nonce, &payload);
    assert_eq!(buf, expected, "就地加密输出必须与分配版逐字节一致（线上格式兼容）");
}
