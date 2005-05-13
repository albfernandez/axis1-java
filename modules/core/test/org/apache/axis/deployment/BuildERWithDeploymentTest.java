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
 
package org.apache.axis.deployment;

import javax.xml.namespace.QName;

import org.apache.axis.AbstractTestCase;
import org.apache.axis.context.EngineContextFactory;
import org.apache.axis.description.OperationDescription;
import org.apache.axis.description.ServiceDescription;
import org.apache.axis.description.Flow;
import org.apache.axis.engine.AxisConfiguration;

public class BuildERWithDeploymentTest extends AbstractTestCase {
    /**
     * @param testName
     */
    public BuildERWithDeploymentTest(String testName) {
        super(testName);
    }

    public void testDeployment() throws Exception {
        String filename = "./target/test-resources/deployment";
        EngineContextFactory builder = new EngineContextFactory();
        AxisConfiguration er = builder.buildEngineContext(filename).getEngineConfig();

        assertNotNull(er);
        assertNotNull(er.getGlobal());
        ServiceDescription service = er.getService(new QName("service2"));
        assertNotNull(service);
        //commentd since there is no service based messgeRecivers
        /*MessageReceiver provider = service.getMessageReceiver();
        assertNotNull(provider);
        assertTrue(provider instanceof RawXMLINOutMessageRecevier);*/
        ClassLoader cl = service.getClassLoader();
        assertNotNull(cl);
        Class.forName("Echo2", true, cl);
        assertNotNull(service.getName());
       //no style for the service 
     //   assertEquals(service.getStyle(),"rpc");

        Flow flow = service.getFaultInFlow();
        assertTrue(flow.getHandlerCount() > 0);
        flow = service.getInFlow();
        assertTrue(flow.getHandlerCount() > 0);
        flow = service.getOutFlow();
        assertTrue( flow.getHandlerCount() > 0);
        assertNotNull(service.getParameter("para2"));

        OperationDescription op = service.getOperation(new QName("opname"));
        assertNotNull(op);

    }
}