#pragma once
#include <windows.h>
#include <functional>

using FileCallback = std::function<void(const wchar_t*)>;

class IOCPEngine {
public:
    IOCPEngine();
    ~IOCPEngine();

    void start(FileCallback cb);
    void enqueue(const wchar_t* path);
    void wait_all();

private:
    HANDLE          m_iocp;
    DWORD           m_thread_count;
    HANDLE*         m_threads;
    FileCallback    m_callback;

    static DWORD WINAPI worker_proc(LPVOID param);
};
