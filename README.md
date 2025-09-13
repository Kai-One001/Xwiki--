##概述
本文档描述了一个安全信息收集脚本的演进路线。该脚本最初为一个针对特定漏洞（以 CVE-2025-55747开始）的简单Xwiki检测工具，信息收集与漏洞扫描框架。
其核心思想是：​​以某个具体漏洞为切入点，抽象出通用功能，然后通过模块化设计不断集成新的漏洞检测、信息收集和非漏洞相关的系统状态探针（有想法，能不能针对py做一款快速漏扫工具呢？定义POC目录，规定好每个POC的输入和输出）。​


##未来
- 会不断更新Xwiki相关信息收集吧
- 增加美观的输出或者高效的日志文件？
- ……


##使用
- python RCE.py -u http://192.168.63.131:8080/

usage: RCE.py [-h] -u URL
RCE.py: error: the following arguments are required: -u/--url
<img width="1262" height="566" alt="image" src="https://github.com/user-attachments/assets/9337da7a-c620-44d9-9a62-909087414d68" />
