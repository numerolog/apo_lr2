cd /home/old_disk/old_developer/apoibas/apoibas_lr2/~SDK
MVNDIR="$(pwd)/~mvn"
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-21.0.5.0.11-1.fc41.x86_64/
export PATH=$JAVA_HOME/bin/:$MVNDIR/bin:$PATH
mvn --global-settings "settings.xml" dependency:copy-dependencies -f workdir/pom.xml -DoutputDirectory=workdir -Dhttps.protocols=TLSv1.2


