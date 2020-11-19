# MemScanner
Analyze Windows x64 Kernel Memory Layout
***

# Build
Build with VS2019 + WDK 10.0.19041.0 <br>
Support Windows 7 ~ Windows 10 20H1 x64, and Not support x86 Platform
***

# Update
2020/11/19 Repair Bsod in Win7/8, and support Finding FileObject By Scanning SectionObject in Win7~Win10  
2020/11/18 Support Find FileObject By Scanning SectionObject(PagedPool Memory)  
2020/10/26 Support EnumDriver By Scanning DriverObject and LDR_DATA_TABLE_ENTRY(NonPagedPool Memory)
***

# Conclusion
- In Win7 DriverObject is not associated with FileObject, within the procedure of MmLoadSystemImage the SectionObject created and deleted immediately at the end; but in Win10 the life cycle of SectionObject is same to DriverObject.  
