#include "loader.h"
#include "dissecters/dissecter_eth.h"

Loader::Loader()
{
    this->dissecterHash.insert(1,new Dissecter_eth());

}

Dissecter *Loader::GetDissecter(qint32 key){
    return this->dissecterHash.value(key);
}
