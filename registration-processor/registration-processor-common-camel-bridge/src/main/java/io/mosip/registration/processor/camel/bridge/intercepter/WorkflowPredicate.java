package io.mosip.registration.processor.camel.bridge.intercepter;

import org.apache.camel.Exchange;
import org.apache.camel.Predicate;
import org.springframework.beans.factory.annotation.Autowired;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.kernel.core.exception.BaseUncheckedException;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.registration.processor.core.abstractverticle.WorkflowInternalActionDTO;
import io.mosip.registration.processor.core.code.WorkflowActionCode;
import io.mosip.registration.processor.core.constant.LoggerFileConstant;
import io.mosip.registration.processor.core.exception.util.PlatformSuccessMessages;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;
import io.vertx.core.json.JsonObject;

public class WorkflowPredicate implements Predicate {
	
	private static final Logger LOGGER = RegProcessorLogger.getLogger(WorkflowPredicate.class);

	@Autowired
	private ObjectMapper objectMapper;

	@Override
	public boolean matches(Exchange exchange) {
		boolean matches=false;

		LOGGER.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.USERID.toString(), "",
				"exchange.getFromEndpoint().toString() " + exchange.getFromEndpoint().toString());
		try {

			String fromAddress = exchange.getFromEndpoint().toString();
		switch(fromAddress) {
		case "workflow://pause-and-request-additional-info":
			processPauseAndRequestAdditionalInfo(exchange);
			matches = true;
			break;
		case "workflow://resume-parent-flow":
			processResumeParentFlow(exchange);
			matches = true;
			break;
		case "workflow://restart-parent-flow":
				processRestartParentFlow(exchange);
			matches = true;
			break;
	    case "workflow://stop-and-notify":
			processStopAndNotify(exchange);
			matches = true;
			break;
		default:
			break;
			}
		} catch (JsonProcessingException e) {
			LOGGER.error("Error in  RoutePredicate::matches {}", e.getMessage());
			throw new BaseUncheckedException(e.getMessage());
		} catch (Exception e) {
			LOGGER.error("Error in  RoutePredicate::matches {}", e.getMessage());
			throw new BaseUncheckedException(e.getMessage());
		}
		return matches;
	}

	private void processRestartParentFlow(Exchange exchange) throws JsonProcessingException {
		String message = (String) exchange.getMessage().getBody();
		JsonObject json = new JsonObject(message);
		WorkflowInternalActionDTO workflowEventDTO = new WorkflowInternalActionDTO();
		workflowEventDTO.setRid(json.getString("rid"));
		workflowEventDTO.setActionCode(WorkflowActionCode.RESTART_PARENT_FLOW.toString());
		workflowEventDTO.setActionMessage(PlatformSuccessMessages.PACKET_RESTART_PARENT_FLOW.getMessage());
		exchange.getMessage().setBody(objectMapper.writeValueAsString(workflowEventDTO));
	}

	private void processStopAndNotify(Exchange exchange) throws JsonProcessingException {
		String message = (String) exchange.getMessage().getBody();
		JsonObject json = new JsonObject(message);
		WorkflowInternalActionDTO workflowEventDTO = new WorkflowInternalActionDTO();
		workflowEventDTO.setRid(json.getString("rid"));
		workflowEventDTO.setActionCode(WorkflowActionCode.STOP_AND_NOTIFY.toString());
		workflowEventDTO.setActionMessage(PlatformSuccessMessages.PACKET_STOP_AND_NOTIFY.getMessage());
		exchange.getMessage().setBody(objectMapper.writeValueAsString(workflowEventDTO));

	}

	private void processResumeParentFlow(Exchange exchange) throws JsonProcessingException {
		String message = (String) exchange.getMessage().getBody();
		JsonObject json = new JsonObject(message);
		WorkflowInternalActionDTO workflowEventDTO = new WorkflowInternalActionDTO();
		workflowEventDTO.setRid(json.getString("rid"));
		workflowEventDTO.setActionCode(WorkflowActionCode.RESUME_PARENT_FLOW.toString());
		workflowEventDTO
				.setActionMessage(PlatformSuccessMessages.PACKET_RESUME_PARENT_FLOW.getMessage());
		exchange.getMessage().setBody(objectMapper.writeValueAsString(workflowEventDTO));

	}

	private void processPauseAndRequestAdditionalInfo(Exchange exchange) throws JsonProcessingException {
		String message = (String) exchange.getMessage().getBody();
		JsonObject json = new JsonObject(message);
		WorkflowInternalActionDTO workflowEventDTO = new WorkflowInternalActionDTO();

		workflowEventDTO.setResumeTimestamp(
				DateUtils.formatToISOString(
						DateUtils.getUTCCurrentDateTime().plusSeconds((Long) exchange.getProperty("pauseFor"))));
		workflowEventDTO.setRid(json.getString("rid"));
		workflowEventDTO.setDefaultResumeAction(WorkflowActionCode.STOP_PROCESSING.toString());
		workflowEventDTO.setActionCode(WorkflowActionCode.PAUSED_FOR_ADDITIONAL_INFO.toString());
		workflowEventDTO.setEventTimestamp(DateUtils.formatToISOString(DateUtils.getUTCCurrentDateTime()));
		workflowEventDTO
				.setActionMessage(PlatformSuccessMessages.PACKET_PAUSED_FOR_ADDITIONAL_INFO.getMessage());
		workflowEventDTO.setSubProcess((String) exchange.getProperty("subProcess"));

		exchange.getMessage().setBody(objectMapper.writeValueAsString(workflowEventDTO));

	}

}
