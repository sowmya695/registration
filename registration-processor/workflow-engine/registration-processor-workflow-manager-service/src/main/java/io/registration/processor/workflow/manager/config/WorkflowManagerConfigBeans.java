package io.registration.processor.workflow.manager.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestTemplate;

import io.mosip.kernel.core.websub.spi.PublisherClient;
import io.mosip.kernel.websub.api.client.PublisherClientImpl;
import io.mosip.registration.processor.core.spi.restclient.RegistrationProcessorRestClientService;
import io.mosip.registration.processor.core.workflow.dto.WorkflowCompletedEventDTO;
import io.mosip.registration.processor.packet.storage.utils.PacketManagerService;
import io.mosip.registration.processor.rest.client.service.impl.RegistrationProcessorRestClientServiceImpl;
import io.registration.processor.workflow.manager.service.WorkflowActionService;
import io.registration.processor.workflow.manager.service.WorkflowSearchService;
import io.registration.processor.workflow.manager.stage.WorkflowActionApi;
import io.registration.processor.workflow.manager.stage.WorkflowActionJob;
import io.registration.processor.workflow.manager.stage.WorkflowInternalActionVerticle;
import io.registration.processor.workflow.manager.stage.WorkflowSearchApi;
import io.registration.processor.workflow.manager.util.WebSubUtil;
import io.registration.processor.workflow.manager.validator.WorkflowActionRequestValidator;
import io.registration.processor.workflow.manager.validator.WorkflowSearchRequestValidator;

@PropertySource("classpath:bootstrap.properties")
@Configuration
public class WorkflowManagerConfigBeans {
	@Bean
	public WorkflowInternalActionVerticle getWorkflowEventUpdateVerticle() {
		return new WorkflowInternalActionVerticle();
	}

	@Bean
	public WorkflowActionApi getWorkFlowActionApi() {
		return new WorkflowActionApi();
	}

	@Bean
	public WorkflowSearchApi getWorkflowSearchApi() {
		return new WorkflowSearchApi();
	}

	@Bean
	public WorkflowActionRequestValidator getWorkflowActionRequestValidator() {
		return new WorkflowActionRequestValidator();
	}

	@Bean
	public WorkflowSearchRequestValidator getWorkflowSearchRequestValidator() {
		return new WorkflowSearchRequestValidator();
	}

	@Bean
	public WorkflowActionService getWorkflowActionService() {
		return new WorkflowActionService();
	}

	@Bean
	public WorkflowSearchService getWorkflowSearchService() {
		return new WorkflowSearchService();
	}

	@Bean
	public PacketManagerService getPacketManagerService() {
		return new PacketManagerService();
	}

	@Bean
	public WebSubUtil getWebSubUtil() {
		return new WebSubUtil();
	}

	@Bean
	public PublisherClient<String, WorkflowCompletedEventDTO, HttpHeaders> getWebPublisherClient() {
		return new PublisherClientImpl<WorkflowCompletedEventDTO>();
	}

	@Bean
	public RestTemplate getRestTemplate() {
		return new RestTemplate();
	}

	@Bean
	public RegistrationProcessorRestClientService<Object> getRegistrationProcessorRestClientService() {
		return new RegistrationProcessorRestClientServiceImpl();
	}

	@Bean
	public WorkflowActionJob getWorkflowActionJob() {
		return new WorkflowActionJob();
	}
}
