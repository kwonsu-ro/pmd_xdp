# Packet Malware Detection With XDP
본 소스코드는 XDP를 이용하여 두개의 NIC로 양방향 통신을 하는 환경에서 악성코드를 탐지하는 프로그램이다.</br>
대상 패킷은 IPv4의 TCP UDP 패킷을 대상으로 악성코드를 검사하고 나머지 패킷은 일반 포워딩을 한다.

# 1. 주요기능
+ 두개의 NIC 환경에서 XSK MAP과 AF_XDP를 이용한 양방향 통신
+ 양방향 통신 시 Yara를 이용하여 패킷의 악성코드 탐지
  
# 2. 네트워크 구성도
네트워크 구성도는 다음과 같다.

<img width="879" height="156" alt="Image" src="https://github.com/user-attachments/assets/43c1d90e-857c-4a13-808e-a7e439f0a52a" />

위 그림과 같이 Client와 Server 사이에 XDP를 이용하여 enp0s3과 enp0s8 NIC 간의 양방향 통신을 하고 Yara로 패킷의 악성코드를 탐지한다.</br>
사용하는 환경에 맞게 NIC와 IP설정을 한다.
> [!IMPORTANT]
> Client와 Server는 **반드시 PMD를 게이트웨어로 설정**해야 한다.

# 3. 개발환경
개발환경은 다음과 같다.
+ **VirtualBox : V 7.0**
+ **Host OS : Windows 11**
+ **Guest OS : Rocky Linux 9.4 x 3**

Guest OS는 Client, PMD, Server 모두 같은 OS를 사용한다. </br>
Client/Server와 PMD의 다른점은 PMD는 NIC가 두개이고 XDP 개발 환경을 설치해야 한다는 점이다.

## 3.1. 제약사항
+ Guest OS 네트워크의 어뎁터 종류는 **반가상 네트워크(virtio-net)** 으로 설정한다.
+ XDP는 **Generic Mode**로 사용한다. 만약 **Netive Mode**를 사용할 수 있는 환경이라면 __src/xdp_util.c__ 파일에서 **SKB Mode** 를
  **Netive Mode**로 수정하여 사용한다.
+ **Yara**를 이용하여 실시간으로 악성코드를 탐지하므로 속도저하가 있을 수 있다.

# 4. 개발환경 구축
개발환경 구축은 다음과 같다.

## 4.1. 필수 패키지 설치
필수 패키지 설치 방법은 다음과 같다.

### 4.1.1. Client/Server
```
# dnf config-manager --set-enabled crb
# dnf -y install epel-release
# dnf -y update
# dnf -y --enablerepo=devel install vim net-tools libcurl tcpdump hping3
# dnf -y install dhcp-client
# dnf -y update
# dnf -y clean all
```
### 4.1.2. PMD
```
# dnf config-manager --set-enabled crb
# dnf -y install epel-release
# dnf -y update
# dnf -y --enablerepo=devel install dkms kernel-devel kernel-headers gcc make bzip2 elfutils-libelf-devel ntsysv vim net-tools libcurl tcpdump teamd tree initscripts systemd-devel
# dnf -y --enablerepo=devel install clang llvm libbpf libbpf-devel libxdp libxdp-devel xdp-tools bpftool
# dnf -y install network-scripts --enablerepo=devel 
# dnf -y install glibc-devel.i686
# dnf -y install dhcp-client
# dnf -y install yara.x86_64 yara-devel.x86_64
# dnf -y update
# dnf -y clean all
```

## 4.2. XDP 개발 환경 설정

### 4.2.1. SELinux disable
SELinux는 disable하는 것을 추천한다.
```
# vim /etc/selinux/config
..........
SELINUX=disabled
..........
```

### 4.2.2. 초기화 스크립트 실행
초기화 스크립트 실행은 다음과 같다.
```
# cd ./script
# ./pmd_init.sh enp0s3 enp0s8
Start initialise NIC
        Initialise ethernet : enp0s3
        Initialise ethernet : enp0s8
End initialise NIC

Start initialise Yara Rules
        Create Yara Rule File for Testing
            Yara Test Rule file : pmd_test.yar
        Create Yara Compile Rules
            Yara Compile Rule path : /etc/yara/rules/compiled_rules.yarc
End initialise Yara Rules
```
+ 초기화 스크립트는 NIC의 초기화와 Yara Rule 초기화를 진행한다. </br>
+ NIC는 사용자의 환경에 맞게 입력하여 사용한다.</br>
+ Yara Rlue은 script src 디렉토리가 있는 위치에 **yara_rules** 디렉토리를 생성하여 Rule을 컴파일 한다.

### 4.2.3. 포워딩 설정
포워딩 설정은 다음과 같다.
```
# vim /etc/sysctl.conf
..........
net.ipv4.ip_forward = 1
..........
```

# 5. 컴파일 및 실행 방법
컴파일 및 실행 방법은 다음과 같다.

## 5.1. 컴파일 방법
```
# ls
Makefile  README.md  script  src  yara_rules
# make clean
# make
# make install
# ls
Makefile  README.md  pmd_xdp  script  src  xdp_prog_kern.o  yara_rules
#
```

## 5.2. 실행 방법
```
# ./pmd_xdp enp0s3 enp0s8
[YARA] 규칙 로드: /etc/yara/rules/compiled_rules.yarc
[YARA] 초기화 완료 (FAST_MODE, timeout=20ms)
<================> Start XDP SPMD <================>
Bridge up: enp0s3 <-> enp0s8 (queue 0, SKB/COPY)
libbpf: elf: skipping unrecognized data section(6) xdp_metadata
libbpf: elf: skipping unrecognized data section(6) xdp_metadata
libbpf: elf: skipping unrecognized data section(6) xdp_metadata
libbpf: elf: skipping unrecognized data section(6) xdp_metadata
libbpf: elf: skipping unrecognized data section(6) xdp_metadata
libbpf: elf: skipping unrecognized data section(6) xdp_metadata
```

# 6. 테스트 방법
테스트 방법은 다음과 갇다.

## 6.1. Server
트래픽이 유입되는지 확인하기 위하여 tcpdump를 실행한다.
```
tcpdump -vvv -i enp0s3 -enn 'arp or ip and port 80'
```

## 6.2. Client
테스트용 Malware 파일을 생성한다.
```
# echo "malware" > /tmp/malware
```

hping3로 Server(10.10.126.4)의 80 포트에 악성코드 셈플 파일을 전송한다.
```
hping3 --fast -S 10.10.126.4 -p 80 -d 100 -E /tmp/malware
HPING 10.10.126.4 (enp0s3 10.10.126.4): S set, 40 headers + 100 data bytes
[main] memlockall(): No such file or directory
Warning: can't disable memory paging!
len=40 ip=10.10.126.4 ttl=63 DF id=0 sport=80 flags=RA seq=0 win=0 rtt=2.6 ms
len=40 ip=10.10.126.4 ttl=63 DF id=0 sport=80 flags=RA seq=1 win=0 rtt=1.0 ms
..........
```

## 6.3. PMD
유입되는 악성코드 패킷이 차단되는지 확인한다.
```
FORWARD Packet:PROTO:[TCP] SRC:(00:00:00:00:00:52) [10.10.56.102:1364] --> DST:(00:00:00:00:00:84) [10.10.126.4:80]
[MAC] IP:10.10.126.4 의 MAC을 갱신했습니다. MAC: 00:00:00:00:00:1c
FORWARD Packet:PROTO:[TCP] SRC:(00:00:00:00:00:1c) [10.10.126.4:80] --> DST:(00:00:00:00:00:7e) [10.10.56.102:1364]
[MAC] IP:10.10.56.102 의 MAC을 갱신했습니다. MAC: 00:00:00:00:00:52
DROP 1 Packet:PROTO:[TCP] SRC:(00:00:00:00:00:52) [10.10.56.102:1365] --> DST:(00:00:00:00:00:84) [10.10.126.4:80]
```

# 참고
악성코드 탐지 시 같은 Client에서 같은 Server의 포트로 계속 악성코드가 유입되는 경우 차단 유지 시간을 갱신하여 계속 차단된다.</br>
악성코드 차단 유지 시간이 해제되는 시간은 60초로 되있고 이시간 동안 Client에서 같은 Server의 포트로 악성코드가 유입되지 않아야 통신이 가능한다.</br>
만약 차단 유지 시간을 수정하고자 할 경우 **src/main.c** 파일의 다음과 같은 부분을 수정하여 컴파일하고 재실행한다.
```
35 // Blocklist 메크로
36 #define BLOCK_DURATION_SEC 60  // 60초 후 자동 해제
```

# 마무리
본 소스코드는 실시간으로 악성코드를 탐지하는 다양한 방법 중에 하나를 선택하여 간단한 방법으로 패킷을 대상으로 실시간으로 악성코드 탐지하는 방법을 사용한다.</br>
본 소스코드를 사용시 속도저하, 오탐 발생, 고속 패킷 전송 시 패킷 유실이 발생할 수 있으며 발생하는 피해는 모두 사용자에게 책임이 있다.</br>
