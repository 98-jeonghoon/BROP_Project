<div align=center>
  <img src="https://capsule-render.vercel.app/api?type=soft&color=gradient&height=300&section=header&text=RCE%20POST%20EXPLOIT%20(in%20blackbox%20situation)&fontSize=40">
</div>

<div align=center>
	<h3>🛠️ Use Tool 🛠️</h3>
</div>

<div align="center">
	<img src="https://img.shields.io/badge/Python-3776AB?style=flat&logo=Python&logoColor=white" />
	<img src="https://img.shields.io/badge/Socket-010101?style=flat&logo=Socket.io&logoColor=white" />
	<img src="https://img.shields.io/badge/Shell Script-008CDD?style=flat&logo=Stripe&logoColor=white" />	
	<br>
	<img src="https://img.shields.io/badge/nmap-19A974?style=flat&logoColor=white" />
  <img src="https://img.shields.io/badge/gdb_peda-C70D2C?style=flat&logoColor=white" />
  <img src="https://img.shields.io/badge/radare-FF00A0?style=flat&logoColor=white" />
  <img src="https://img.shields.io/badge/Linux-FCC624?style=flat&logo=Linux&logoColor=white" />
	<br>
</div>

## Introduction
소스코드 및 바이너리가 주어지지 않은 상태, 즉 블랙박스 상황에서 프로세스의 상태나 출력 내용으로 공격을 수행하는 기법을 BROP(Blind Return Oriented Programming)라고 한다. 
BROP공격은 위해서는 서비스가 충돌이 발생한 후 서비스의 반응을 보며 이를 이용하여 원격 공격 코드를 구성할 수 있다. 
또한 BROP공격은 유출된 Gadget을 사용하여 메모리를 덤프 또는 서비스 프로그램의 바이너리를 추출 가능 하다. 
독점 소프트웨어를 공격하는 것 외에도 바이너리가 공개되지 않은 오픈 소스 소프트웨어를 공격하는 데 매우 유용하다. 이러한 것들을 이용하여 프로젝트를 구상하였다.

## 테스트 서버 구축
```sh
# 명령어 하나만으로 간단하게 영구적으로 서버 구축을 위한 socat을 사용
#!/bin/sh
while true; do
  num=ps -ef | grep "socat" | grep -v "grep" | wc -l
  if [ $num -eq 0 ]; then
    socat tcp-4-listen:10001, reuseaddr, fork exec: ./brop & done
```

## 포트 스캐닝
<h3> 서버에 로그가 남지 않는 스텔스 스캔을 사용 (Nmap) </h3>
<img src="https://user-images.githubusercontent.com/39319854/214398536-373f69fd-ad6f-498a-8c97-532403cdb887.png">
스텔스 스캔으로 얻은 well-known port를 제외한 포트중 대화형 프로그램 채택 과정


## 공격과정
### 공격 타겟 분석 및 공격
- 스택 오버플로우 크기 확인
- Stop gadget 찾기
- BROP gadget 찾기
- Puts_plt 찾기
- Memory Dump 하기
- Library 주소 유출과정
- 최종 Exploit

#### 공격 과정을 종합한 코드 : https://github.com/98-jeonghoon/BROP_Project/blob/c3a6f714c5b13c806217cf8758171409a1054240/code/ex.py

## 공격 후 지속되는 공격을 위한 백도어 심기
<h3> 위치 : /ect/crontab </h3>
<img src="https://user-images.githubusercontent.com/39319854/214401329-a70af25c-d9bc-4637-9ccb-746aeabdbcb1.png">
<h3> 결과 확인 </h3>
<img src="https://user-images.githubusercontent.com/39319854/214401691-42a02b6f-caf4-4536-bde5-7b5ba0ea8629.png">

## BROP에 취약한 Server Binary를 발견하는 Tool 제작
https://github.com/98-jeonghoon/BROP_Project/blob/c3a6f714c5b13c806217cf8758171409a1054240/code/tool.py

## 최종 10001, 10002, 10003 포트에 바이너리를 실행시킨 후 툴 작동결과 확인
<img src="https://user-images.githubusercontent.com/39319854/214402193-2f87262f-284d-4ee2-866f-9f8eff4fd7e3.png">

