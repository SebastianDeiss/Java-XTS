# XTS mode implementation for Java #

This repository contains a free implementation of the XTS mode specified in the IEEE P1619(TM)/D16 Standard for Cryptographic Protection of Data on Block-Oriented Storage Devices.  
 
The IEEE standard specifies XTS with AES only, but this implementation allows using XTS with various block ciphers.


## License ##
This software is released under the BSD 2-Clause License.  
For details see [License.txt](./License.txt).


## Supported Algorithms ##
* AES  
* Twofish  
* Serpent  
* RC6  


## Dependencies ##
None. It includes the required parts of [Bouncy Castle](https://bouncycastle.org/java.html).
