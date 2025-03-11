package apo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication(exclude = DataSourceAutoConfiguration.class)
public class Lr2Application 
{
    
	public static void main(String[] args) 
	{
		SpringApplication app = new SpringApplication(Lr2Application.class);
		app.run(args);
	}
	
}

