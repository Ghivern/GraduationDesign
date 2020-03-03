#include "dissect.h"

//Public Methods
Dissect::Dissect(Capture *captureT)
{
    this->dissect_result_list = new dissect_result_list_t;
    this->capture = captureT;
    this->loader = new Loader();
    qDebug() << "dissect 初始化完成";
}

Dissect::~Dissect(){
}

dissect_result_list_t* Dissect::GetDissectResList(){
    return this->dissect_result_list;
}

Loader *Dissect::GetLoader(){
    return this->loader;
}


//Protected Methods
void Dissect::run(){
    qDebug() << "dissectT start";
    qint64 index = 0;
    while ( capture->isRunning() || (this->capture->GetListRaw()->length() > index && this->capture->GetListInfo()->length()  > index)) {
        if(this->capture->GetListRaw()->length() > index && this->capture->GetListInfo()->length()  > index)
        {
            while (!this->capture->GetMutex()->tryLock()) {
                ;
            }
            this->loader->GetDissecter(this->capture->GetHandle()->GetLinkType())->dissect(
                        this->capture->GetListRaw()->at(index),
                        this->capture->GetListInfo()->at(index),
                        this->dissect_result_list
                        );
            this->capture->GetMutex()->unlock();

            emit onePacketDissected(this->dissect_result_list->at(index));
            emit print(this->dissect_result_list->at(index));

            index++;
            if(this->capture->GetListRaw()->length() - this->dissect_result_list->length() >= 2)
                this->setPriority(QThread::Priority::HighestPriority);
            else
                this->setPriority(QThread::Priority::NormalPriority);
        }
    }
    quit();
}

void Dissect::clear(){
    if(this->dissect_result_list->length() != 0){
        this->dissect_result_list->clear();
    }
}

//Private Methods

//Public Slots
void Dissect::StartDissect(){
    this->clear();
    this->start();
}


