# Linux Netfilter Kernel Module

Simple linux netfilter module that logs 5 different types of TCP packets in kernel logs - ACK, SYN, FIN, XMAS and NULL packet.

**Note**: You can find detailed information about tthe module in [report.pdf] (https://github.com/HarishFulara07/NS-Linux-Netfilter-Kernel-Module/blob/master/report.pdf)

# How to run
1. Compile using makefile - 'make all'
2. Add the module to the kernel modules - 'sudo isnmod Assignment1.ko'
3. View logged packets - 'sudo dmesg'
4. To remove the kernel module - 'sudo rmmod Assignment1'
