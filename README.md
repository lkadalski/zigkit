# zigkit
Opinionated kit for zig development. 

## Introduction
This project is to create my own set of tools for Zig Development. It consists of single file libraries which you can use in your app development. 


##Encoding, Hashing, Encryption
I had hard time to tackle differences between those in my early days of programming. The nature of those is actually really simple.
### Encoding
Is a reversible transformation of specific input to another format. It's mainly purpose is send data in compact way between two processes/machines.
Examples:
UTF-8, Base64.
Both are used to transform data between two machines. Where UTF-8 stands for a standard in text encoding, the base64 is standard for encoding mail attachments.
We usually also keep secrets in kubernetes in base64 format. 
