# RCE & POST EXPLOIT (in blackbox situation)

## Introduction
소스코드 및 바이너리가 주어지지 않은 상태, 즉 블랙박스 상황에서 프로세스의 상태나 출력 내용으로 공격을 수행하는 기법을 BROP(Blind Return Oriented Programming)라고 한다. BROP공격은 위해서는 서비스가 충돌이 발생한 후 서비스의 반응을 보며 이를 이용하여 원격 공격 코드를 구성할 수 있다. 또한 BROP공격은 유출된 Gadget을 사용하여 메모리를 덤프 또는 서비스 프로그램의 바이너리를 추출 가능 하다. 독점 소프트웨어를 공격하는 것 외에도 바이너리가 공개되지 않은 오픈 소스 소프트웨어를 공격하는 데 매우 유용하다. 이러한 것들을 이용하여 프로젝트를 구상하였다.

## 자세한 코드 및 프로젝트 설명은 다음을 참조해주세요.

-[report](https://github.com/98-jeonghoon/BROP_Project/blob/main/report/report.docx)
