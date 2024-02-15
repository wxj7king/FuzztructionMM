// C++ program to illustrate the binary semaphores 
#include <iostream> 
#include <semaphore> 
#include <mutex>
#include <thread> 
#include <queue>

// Initialize with a count of 1 (binary) 

std::binary_semaphore full_s1(1); 
std::binary_semaphore full_s2(0);
int full_count = 0;

std::binary_semaphore empty_s1(1); 
std::binary_semaphore empty_s2(0);
int empty_count = 4;

std::queue<int> buffer;
int global_exit = 0;

std::mutex m;

void ppost(int f){
    if (f == 1){
        full_s1.acquire();
        //full_count++;
        if (full_count > 0){
            full_s1.release();
        }else{
            full_s2.release();
            full_s1.release();
        }
        full_count++;
        printf(" post full: %d\n", full_count);
    }else{
        empty_s1.acquire();
        //empty_count++;
        if (empty_count > 0){
            empty_s1.release();
        }else{
            empty_s2.release();
            empty_s1.release();
        }
        empty_count++;
        printf(" post empty: %d\n", empty_count);
    }
}

int pwait(int f){
    if (f == 1){
        full_s1.acquire();
        full_count--;
        printf("wait full: %d\n", full_count);
        if (full_count <= 0){
            full_s1.release();
            while(true){
                if(!full_s2.try_acquire()){
                    if (global_exit) return 1;
                }else{
                    break;
                }
            }
            
        }else{
            full_s1.release();
        }
    }else{
        empty_s1.acquire();
        empty_count--;
        printf("wait empty: %d\n", empty_count);
        if (empty_count <= 0){
            empty_s1.release();
            while(true){
                if(!empty_s2.try_acquire()){
                    if (global_exit) return 1;
                }else{
                    break;
                }
            }
        }else{
            empty_s1.release();
        }
    }
    return 0;
    
}

void worker(int id) 
{
    while(true){
        //std::this_thread::sleep_for(std::chrono::milliseconds(200));
        // aquire semaphore 
        if (pwait(1)) break; 
        m.lock();
        int data = buffer.front();
        buffer.pop();
        std::cout << "Thread " << id << ", Consumed: " << data << std::endl; 
        m.unlock();
        ppost(0);
        
    } 
	
} 


// driver code 
int main() 
{   
    std::thread threads[4];
    for (int i = 0; i < 4; i++){
        threads[i] = std::thread(worker, i);
    }
	//std::thread t1(worker, 1); 
	//std::thread t2(worker, 2); 
    for (int i = 0; i < 5; i ++){
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        pwait(0);
        m.lock();
        buffer.push(i);
        std::cout << "Produced: " << i << std::endl;
        m.unlock();
        ppost(1);
        
    }
    
    while(true){
        //printf("value: %d\n", full_count);
        //std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (full_count == -4){
            global_exit = 1;
            break;
        }
    }
    for (int i = 0; i < 4; i ++){
        threads[i].join();
    }
    
	return 0; 
}
