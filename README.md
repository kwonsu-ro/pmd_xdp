# Packet Malware Detection With XDP
본 프로젝트는 XDP를 이용하여 두개의 NIC로 양방향 통신을 하는 환경에서 악성코드를 탐지하는 프로젝트이다.

## 주요기능
+ 두개의 NIC 환경에서 XSK MAP과 AF_XDP를 이용한 양방향 통신
+ 양방향 통신 시 Yara를 이용하여 패킷의 악성코드 탐지
  
## 네트워크 구성도
네트워크 구성도는 다음과 같다.

<img width="879" height="156" alt="Image" src="https://github.com/user-attachments/assets/43c1d90e-857c-4a13-808e-a7e439f0a52a" />

위 그림과 같이 Client와 Server 사이에 XDP를 이용하여 enp0s3과 enp0s8 NIC 간의 양방향 통신을 하고 Yara로 패킷의 악성코드를 탐지한다. 

## 개발환경
개발환경은 다음과 같다.
+ VirtualBox : V 7.0
+ Host OS : Windows 11
+ Guest OS : Rocky Linux 9.4 x 3

Guest OS는 Client, PMD, Server 모두 같은 OS를 사용한다. Client/Server와 PMD의 다른점은 PMD는 NIC가 두개이고 XDP 개발 환경을 설치해야 한다는 점이다.

### 제약사항
+ Guest OS 네트워크의 어뎁터 종류는 **반가상 네트워크(virtio-net)** 으로 설정한다.
+ XDP는 Generic Mode로 사용한다. 만약 Netive Mode를 사용할 수 있는 환경이라면 __src/xdp_util.c__ 파일에서 **SKB Mode** 를
  **Netive Mode**로 수정하여 사용한다.
+ Yara를 이용하여 실시간으로 악성코드를 탐지하므로 속도저하가 있을 수 있다.

## 개발환경 구축
개발환경 구축은 다음과 같다.

### 필수 패키지 설치
필수 패키지 설치는 PMD에 설치한다.
필수 패키지 설치 방법은 다음과 같다.
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

### XDP 개발 환경 설정

#### SELinux disable
SELinux는 disable하는 것을 추천한다.
```
# vim /etc/selinux/config
..........
SELINUX=disabled
..........
```

#### ethtool 설정 및 확인
```
# ethtool -L enp0s3 combined 1
# ethtool -L enp0s8 combined 1
# ethtool -l enp0s3
Channel parameters for enp0s3:
Pre-set maximums:
RX:             n/a
TX:             n/a
Other:          n/a
Combined:       1
Current hardware settings:
RX:             n/a
TX:             n/a
Other:          n/a
#
# ethtool -l enp0s8
Channel parameters for enp0s8:
Pre-set maximums:
RX:             n/a
TX:             n/a
Other:          n/a
Combined:       1
Current hardware settings:
RX:             n/a
TX:             n/a
Other:          n/a
#
# ethtool -K enp0s3 tso off gso off gro off lro off rxvlan off
# ethtool -K enp0s8 tso off gso off gro off lro off rxvlan off
```

#### Pormisc 설정
```
# ethtool -K enp0s3 tso off gso off gro off lro off rxvlan off
# ethtool -K enp0s8 tso off gso off gro off lro off rxvlan off
```


## 개발자
+ **노권수** : kwonsu@empas.com

```
dnf 
```
