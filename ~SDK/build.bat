cd /d %~dp0
SET MVNDIR="~mvn"
SET PATH=%PATH%;%MVNDIR%/bin
SET JAVA_HOME=""C:/Program Files/Java/jdk1.8.0_201""
mvn --global-settings "settings.xml" package -f workdir/pom.xml -DoutputDirectory=workdir -Dhttps.protocols=TLSv1.2
pause
pause