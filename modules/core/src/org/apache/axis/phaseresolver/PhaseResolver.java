/*
* Copyright 2004,2005 The Apache Software Foundation.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.apache.axis.phaseresolver;

import org.apache.axis.context.ConfigurationContext;
import org.apache.axis.description.*;
import org.apache.axis.engine.AxisConfiguration;
import org.apache.axis.engine.AxisFault;
import org.apache.axis.engine.AxisSystemImpl;
import org.apache.axis.phaseresolver.util.PhaseValidator;

import javax.xml.namespace.QName;
import java.util.*;

/**
 * Class PhaseResolver
 */
public class PhaseResolver {
    /**
     * Field axisConfig
     */
    private final AxisConfiguration axisConfig;

    /**
     * Field axisService
     */
    private ServiceDescription axisService;


    /**
     * Field phaseHolder
     */
    private PhaseHolder phaseHolder;

    /**
     * default constructor , to obuild chains for GlobalDescription
     *
     * @param engineConfig
     */
    public PhaseResolver(AxisConfiguration engineConfig) {
        this.axisConfig = engineConfig;
    }

    /**
     * Constructor PhaseResolver
     *
     * @param engineConfig
     * @param serviceContext
     */
    public PhaseResolver(AxisConfiguration engineConfig,
                         ServiceDescription serviceContext) {
        this.axisConfig = engineConfig;
        this.axisService = serviceContext;
    }

    /**
     * Method buildchains
     *
     * @throws PhaseException
     * @throws AxisFault
     */
    public void buildchains() throws PhaseException, AxisFault {
        HashMap operations = axisService.getOperations();
        Collection col = operations.values();
        for (Iterator iterator = col.iterator(); iterator.hasNext();) {
            OperationDescription operation = (OperationDescription) iterator.next();
            for (int i = 1; i < 5; i++) {
                buildExcutionChains(i, operation);
            }
        }
    }

    private void buildModuleHandlers(ArrayList allHandlers, ModuleDescription module, int flowtype) throws PhaseException {
        Flow flow = null;
        switch (flowtype) {
            case PhaseMetadata.IN_FLOW:
                {
                    flow = module.getInFlow();
                    break;
                }
            case PhaseMetadata.OUT_FLOW:
                {
                    flow = module.getOutFlow();
                    break;
                }
            case PhaseMetadata.FAULT_IN_FLOW:
                {
                    flow = module.getFaultInFlow();
                    break;
                }
            case PhaseMetadata.FAULT_OUT_FLOW:
                {
                    flow = module.getFaultOutFlow();
                    break;
                }
        }
        if (flow != null) {
            for (int j = 0; j < flow.getHandlerCount(); j++) {
                HandlerDescription metadata = flow.getHandler(j);

                if (!PhaseValidator.isSystemPhases(metadata.getRules().getPhaseName())) {
                    allHandlers.add(metadata);
                } else {
                    throw new PhaseException("Service specifi module can not refer system pre defined phases : "
                            + metadata.getRules().getPhaseName());
                }
            }
        }
    }

    /**
     * this opeartion is used to build all the three cahins ,
     * so type varible is used to difrenciate them
     * type = 1 inflow
     * type = 2 out flow
     * type = 3 fault flow
     *
     * @param type
     * @throws AxisFault
     * @throws PhaseException
     */
    private void buildExcutionChains(int type, OperationDescription operation)
            throws AxisFault, PhaseException {
        int flowtype = type;
        ArrayList allHandlers = new ArrayList();
        ModuleDescription module;
        Flow flow = null;

        ///////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////// SERVICE HANDLERS ///////////////////////////////////////////////
        switch (flowtype) {
            case PhaseMetadata.IN_FLOW:
                {
                    flow = axisService.getInFlow();
                    break;
                }
            case PhaseMetadata.OUT_FLOW:
                {
                    flow = axisService.getOutFlow();
                    break;
                }
            case PhaseMetadata.FAULT_IN_FLOW:
                {
                    flow = axisService.getFaultInFlow();
                    break;
                }
            case PhaseMetadata.FAULT_OUT_FLOW:
                {
                    flow = axisService.getFaultOutFlow();
                    break;
                }
        }
        if (flow != null) {
            for (int j = 0; j < flow.getHandlerCount(); j++) {
                HandlerDescription metadata = flow.getHandler(j);

                // todo change this in properway
                if (metadata.getRules().getPhaseName().equals("")) {
                    throw new PhaseException("Phase dose not specified");
                }
                allHandlers.add(metadata);
            }
        }

        ///////////////////////////////////////////////////////////////////////////////////////
        ///////////////////// SERVICE MODULE HANDLERS ////////////////////////////////////////////////
        Collection collection = axisService.getModules();
        Iterator itr = collection.iterator();
        while (itr.hasNext()) {
            QName moduleref = (QName) itr.next();
            module = axisConfig.getModule(moduleref);
            if (module != null) {
                buildModuleHandlers(allHandlers, module, flowtype);
            }
        }
        ///////////////////////////////////////////////////////////////////////////////////////
        ///////////////////// OPERATION MODULES ////////////////////////////////////////////////
        Collection opmodule = operation.getModules();
        Iterator opitr = opmodule.iterator();
        while (opitr.hasNext()) {
            QName moduleref = (QName) opitr.next();
            module = axisConfig.getModule(moduleref);
            if (module != null) {
                buildModuleHandlers(allHandlers, module, flowtype);
            }
        }

        switch (flowtype) {
            case PhaseMetadata.IN_FLOW:
                {
                    phaseHolder = new PhaseHolder(operation.getRemainingPhasesInFlow());
                    break;
                }
            case PhaseMetadata.OUT_FLOW:
                {
                    phaseHolder = new PhaseHolder(operation.getPhasesOutFlow());
                    break;
                }
            case PhaseMetadata.FAULT_IN_FLOW:
                {
                    phaseHolder = new PhaseHolder(operation.getPhasesInFaultFlow());
                    break;
                }
            case PhaseMetadata.FAULT_OUT_FLOW:
                {
                    phaseHolder = new PhaseHolder(operation.getPhasesOutFaultFlow());
                    break;
                }
        }
        for (int i = 0; i < allHandlers.size(); i++) {
            HandlerDescription handlerMetaData =
                    (HandlerDescription) allHandlers.get(i);
            phaseHolder.addHandler(handlerMetaData);
        }
        phaseHolder.getOrderedHandlers();
    }

    /**
     * Method buildTranspotsChains
     *
     * @throws PhaseException
     */
    public void buildTranspotsChains() throws PhaseException {
        HashMap axisTransportIn = axisConfig.getTransportsIn();
        HashMap axisTransportOut = axisConfig.getTransportsOut();

        Collection colintrnsport = axisTransportIn.values();
        for (Iterator iterator = colintrnsport.iterator();
             iterator.hasNext();) {
            TransportInDescription transport = (TransportInDescription) iterator.next();
            buildINTransportChains(transport);
        }

        Collection colouttrnsport = axisTransportOut.values();
        for (Iterator iterator = colouttrnsport.iterator();
             iterator.hasNext();) {
            TransportOutDescription transport = (TransportOutDescription) iterator.next();
            buildOutTransportChains(transport);
        }
    }


    private void buildINTransportChains(TransportInDescription transport)
            throws PhaseException {
        //TODO Fix me
        /*Flow flow = null;
        for (int type = 1; type < 4; type++) {
        phaseHolder = new PhaseHolder(axisConfig);
        phaseHolder.setFlowType(type);
        switch (type) {
        case PhaseMetadata.IN_FLOW:
        {
        flow = transport.getInFlow();
        break;
        }
        case PhaseMetadata.FAULT_IN_FLOW:
        {
        flow = transport.getFaultFlow();
        break;
        }
        }
        if (flow != null) {
        for (int j = 0; j < flow.getHandlerCount(); j++) {
        HandlerDescription metadata = flow.getHandler(j);

        // todo change this in properway
        if (metadata.getRules().getPhaseName().equals("")) {
        throw new PhaseException("Phase dose not specified");
        }
        phaseHolder.addHandler(metadata);
        }
        }
        phaseHolder.buildTransportChain(transport, type);
        }*/
    }


    /**
     * Method buildTransportChains
     *
     * @param transport
     * @throws PhaseException
     */
    private void buildOutTransportChains(TransportOutDescription transport)
            throws PhaseException {
        //TODO fix me
        /*Flow flow = null;
        for (int type = 1; type < 4; type++) {
        phaseHolder = new PhaseHolder(axisConfig);
        phaseHolder.setFlowType(type);
        switch (type) {
        case PhaseMetadata.OUT_FLOW:
        {
        flow = transport.getOutFlow();
        break;
        }
        case PhaseMetadata.FAULT_OUT_FLOW:
        {
        flow = transport.getFaultFlow();
        break;
        }
        }
        if (flow != null) {
        for (int j = 0; j < flow.getHandlerCount(); j++) {
        HandlerDescription metadata = flow.getHandler(j);

        // todo change this in properway
        if (metadata.getRules().getPhaseName().equals("")) {
        throw new PhaseException("Phase dose not specified");
        }
        phaseHolder.addHandler(metadata);
        }
        }
        phaseHolder.buildTransportChain(transport, type);
        }*/
    }

    /**
     * Method buildGlobalChains
     *
     * @throws AxisFault
     * @throws PhaseException
     */
    public ConfigurationContext buildGlobalChains()
            throws AxisFault, PhaseException {
        ConfigurationContext engineContext = new ConfigurationContext(axisConfig);
        GlobalDescription global = axisConfig.getGlobal();
        List modules = (List) global.getModules();
        int count = modules.size();
        QName moduleName;
        ModuleDescription module;
        Flow flow = null;
        for (int type = 1; type < 5; type++) {
            switch (type) {
                case PhaseMetadata.IN_FLOW:
                    {
                        phaseHolder = new PhaseHolder(((AxisSystemImpl) axisConfig).getInPhasesUptoAndIncludingPostDispatch());
                        break;
                    }
                case PhaseMetadata.OUT_FLOW:
                    {
                        phaseHolder = new PhaseHolder(((AxisSystemImpl) axisConfig).getOutFlow());
                        break;
                    }
                case PhaseMetadata.FAULT_IN_FLOW:
                    {
                        phaseHolder = new PhaseHolder(((AxisSystemImpl) axisConfig).getInFaultFlow());
                        break;
                    }
                case PhaseMetadata.FAULT_OUT_FLOW:
                    {
                        phaseHolder = new PhaseHolder(((AxisSystemImpl) axisConfig).getOutFaultFlow());
                        break;
                    }
            }
            //TODO NOTE : the following section commented since are not going to init all the module
            //if they are not refered by some one  (Deepal)
            /*Collection col = ((AxisSystemImpl) axisConfig).getModules().values();
            for (Iterator iterator = col.iterator(); iterator.hasNext();) {
            ModuleDescription axismodule = (ModuleDescription) iterator.next();
            switch (type) {
            case PhaseMetadata.IN_FLOW:
            {
            flow = axismodule.getInFlow();
            break;
            }
            case PhaseMetadata.OUT_FLOW:
            {
            flow = axismodule.getOutFlow();
            break;
            }
            case PhaseMetadata.FAULT_IN_FLOW:
            {
            flow = axismodule.getFaultInFlow();
            break;
            }
            case PhaseMetadata.FAULT_OUT_FLOW:
            {
            flow = axismodule.getFaultOutFlow();
            break;
            }
            }
            if (flow != null) {
            for (int j = 0; j < flow.getHandlerCount(); j++) {
            HandlerDescription metadata = flow.getHandler(j);

            if(PhaseValidator.isSystemPhases(metadata.getRules().getPhaseName())){
            phaseHolder.addHandler(metadata);
            } else {
            throw new PhaseException("Global module can not refer service specific phases : "
            + metadata.getRules().getPhaseName());
            }
            }
            }
            }*/
            ////////////////////////////////////////////////////////////////////////////////////
            /////////////////// Modules refered by server.xml //////////////////////////////////
            ////////////////////////////////////////////////////////////////////////////////////
            for (int intA = 0; intA < count; intA++) {
                moduleName = (QName) modules.get(intA);
                module = axisConfig.getModule(moduleName);
                switch (type) {
                    case PhaseMetadata.IN_FLOW:
                        {
                            flow = module.getInFlow();
                            break;
                        }
                    case PhaseMetadata.OUT_FLOW:
                        {
                            flow = module.getOutFlow();
                            break;
                        }
                    case PhaseMetadata.FAULT_IN_FLOW:
                        {
                            flow = module.getFaultInFlow();
                            break;
                        }
                    case PhaseMetadata.FAULT_OUT_FLOW:
                        {
                            flow = module.getFaultOutFlow();
                            break;
                        }
                }
                if (flow != null) {
                    for (int j = 0; j < flow.getHandlerCount(); j++) {
                        HandlerDescription metadata = flow.getHandler(j);
                        if (PhaseValidator.isSystemPhases(metadata.getRules().getPhaseName())) {
                            phaseHolder.addHandler(metadata);
                        } else {
                            throw new PhaseException("Global module can not refer service specific phases : "
                                    + metadata.getRules().getPhaseName());
                        }
                    }
                }
            }
            phaseHolder.getOrderedHandlers();
        }
        return engineContext;
    }
}