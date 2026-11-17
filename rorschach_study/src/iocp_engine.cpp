#include "iocp_engine.h"
#include <cstring>

struct WorkItem {
    wchar_t path[MAX_PATH];
};

IOCPEngine::IOCPEngine() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    m_thread_count = si.dwNumberOfProcessors * 2;
    m_iocp    = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    m_threads = new HANDLE[m_thread_count];
}

IOCPEngine::~IOCPEngine() {
    for (DWORD i = 0; i < m_thread_count; i++)
        PostQueuedCompletionStatus(m_iocp, 0, 0, NULL);
    WaitForMultipleObjects(m_thread_count, m_threads, TRUE, INFINITE);
    for (DWORD i = 0; i < m_thread_count; i++)
        CloseHandle(m_threads[i]);
    delete[] m_threads;
    CloseHandle(m_iocp);
}

void IOCPEngine::start(FileCallback cb) {
    m_callback = cb;
    for (DWORD i = 0; i < m_thread_count; i++)
        m_threads[i] = CreateThread(NULL, 0, worker_proc, this, 0, NULL);
}

void IOCPEngine::enqueue(const wchar_t* path) {
    WorkItem* item = new WorkItem;
    wcsncpy_s(item->path, path, MAX_PATH);
    PostQueuedCompletionStatus(m_iocp, 1,
        reinterpret_cast<ULONG_PTR>(item), NULL);
}

void IOCPEngine::wait_all() {
    WaitForMultipleObjects(m_thread_count, m_threads, TRUE, INFINITE);
}

DWORD WINAPI IOCPEngine::worker_proc(LPVOID param) {
    auto* engine = reinterpret_cast<IOCPEngine*>(param);
    DWORD bytes; ULONG_PTR key; OVERLAPPED* ov;

    while (true) {
        BOOL ok = GetQueuedCompletionStatus(
            engine->m_iocp, &bytes, &key, &ov, INFINITE);
        if (!ok || key == 0) break;
        auto* item = reinterpret_cast<WorkItem*>(key);
        engine->m_callback(item->path);
        delete item;
    }
    return 0;
}
