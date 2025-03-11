cd /d %~dp0
SET MVNDIR="~mvn"
SET PATH=%PATH%;%MVNDIR%/bin
mvn --global-settings "settings.xml" dependency:copy-dependencies -f workdir/pom.xml -DoutputDirectory=workdir -Dhttps.protocols=TLSv1.2
pause
pause