package io.mosip.registration.processor.workflow.manager.util;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.websub.spi.PublisherClient;
import io.mosip.kernel.websub.api.exception.WebSubClientException;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;
import io.mosip.registration.processor.core.workflow.dto.WorkflowCompletedEventDTO;

@Component
public class WebSubUtil {
	@Autowired
	private PublisherClient<String, WorkflowCompletedEventDTO, HttpHeaders> publisher;

	@Value("${mosip.regproc.workflow.complete.topic}")
	private String workflowCompleteTopic;

	@Value("${websub.publish.url}")
	private String webSubPublishUrl;

	/** The reg proc logger. */
	private static Logger regProcLogger = RegProcessorLogger.getLogger(WebSubUtil.class);

	@PostConstruct
	private void registerTopic() {
		try {
			publisher.registerTopic(workflowCompleteTopic, webSubPublishUrl);
		} catch (WebSubClientException exception) {
			regProcLogger.warn(exception.getMessage());
		}
	}

	public void publishEvent(WorkflowCompletedEventDTO workflowCompletedEventDTO) throws WebSubClientException {
		String rid = workflowCompletedEventDTO.getInstanceId();
		HttpHeaders httpHeaders = new HttpHeaders();
		publisher.publishUpdate(workflowCompleteTopic, workflowCompletedEventDTO, MediaType.APPLICATION_JSON_UTF8_VALUE,
				httpHeaders, webSubPublishUrl);
		regProcLogger.info("Publish the update successfully  for registration id {}", rid);

	}

}