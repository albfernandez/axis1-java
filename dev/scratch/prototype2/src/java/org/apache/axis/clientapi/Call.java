package org.apache.axis.clientapi;

import org.apache.axis.engine.*;
import org.apache.axis.impl.engine.EngineRegistryImpl;
import org.apache.axis.impl.llom.builder.StAXBuilder;
import org.apache.axis.impl.llom.builder.StAXSOAPModelBuilder;
import org.apache.axis.description.AxisGlobal;
import org.apache.axis.om.*;
import org.apache.axis.context.MessageContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import java.net.URL;
import java.net.URLConnection;
import java.io.IOException;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Iterator;

/**
 * Copyright 2001-2004 The Apache Software Foundation.
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *         Dec 16, 2004
 *         12:28:00 PM
 */
public class Call {
    private EngineRegistry registry;
    protected Log log = LogFactory.getLog(getClass());
    private EndpointReferance targetEPR;


    public Call() {
        //TODO look for the Client XML and creatre a Engine registy
        this.registry = new EngineRegistryImpl(new AxisGlobal());
    }

    public void setTo(EndpointReferance EPR){
        this.targetEPR = EPR;

    }

    /**
     * todo
     * inoder to have asyn support for tansport , it shoud call this method
     * @param transport
     */
    public void setListenerTransport(String transport, boolean blocked){

    }
    /**
     * todo
     * @param action
     */
    public void setAction(String action){

    }


    /**
     * Fire and forget MEP
     * todo
     * @param envelope
     */
    public void sendAsync(SOAPEnvelope envelope) throws AxisFault {
        //todo ask srinath about this URL, frorm where I can get it :)
        URL url = null;
        try{
            final URLConnection urlConnect;
            urlConnect = url.openConnection();
            final AxisEngine engine = new AxisEngine(registry);
            urlConnect.setDoOutput(true);


            MessageContext msgctx = new MessageContext(registry);
            msgctx.setEnvelope(envelope);

            OutputStream out = urlConnect.getOutputStream();
            msgctx.setProperty(MessageContext.TRANSPORT_DATA, out);
            msgctx.setProperty(MessageContext.TRANSPORT_TYPE, TransportSenderLocator.TRANSPORT_HTTP);
            msgctx.setProperty(MessageContext.REQUEST_URL, url);

            engine.send(msgctx);

        }catch (IOException e){
            throw AxisFault.makeFault(e);
        }
    }
    public void send(SOAPEnvelope envelope) throws AxisFault {
        //todo ask srinath about this URL, frorm where I can get it :)
        URL url = null;
        try{
            final URLConnection urlConnect;
            urlConnect = url.openConnection();
            final AxisEngine engine = new AxisEngine(registry);
            urlConnect.setDoOutput(true);


            MessageContext msgctx = new MessageContext(registry);
            msgctx.setEnvelope(envelope);

            OutputStream out = urlConnect.getOutputStream();
            msgctx.setProperty(MessageContext.TRANSPORT_DATA, out);
            msgctx.setProperty(MessageContext.TRANSPORT_TYPE, TransportSenderLocator.TRANSPORT_HTTP);
            msgctx.setProperty(MessageContext.REQUEST_URL, url);
            engine.send(msgctx);

            //todo dose the 202 response  come throgh the same connection
            MessageContext response = createIncomingMessageContext(urlConnect.getInputStream(), engine);
            response.setServerSide(false);
            engine.receive(response);


        }catch (IOException e){
            throw AxisFault.makeFault(e);
        }

    }

    public SOAPEnvelope  sendReceive(SOAPEnvelope envelope) throws AxisFault {
        //todo ask srinath about this URL, frorm where I can get it :)
        URL url = null;
        try {
            URLConnection urlConnect = url.openConnection();
            urlConnect.setDoOutput(true);

            AxisEngine engine = new AxisEngine(registry);
            MessageContext msgctx = new MessageContext(registry);
            msgctx.setEnvelope(envelope);

            OutputStream out = urlConnect.getOutputStream();
            msgctx.setProperty(MessageContext.TRANSPORT_DATA, out);
            msgctx.setProperty(MessageContext.TRANSPORT_TYPE, TransportSenderLocator.TRANSPORT_HTTP);
            msgctx.setProperty(MessageContext.REQUEST_URL, url);
            engine.send(msgctx);

            MessageContext response = createIncomingMessageContext(urlConnect.getInputStream(), engine);
            response.setServerSide(false);
            engine.receive(response);

            SOAPEnvelope resenvelope = response.getEnvelope();

            SOAPBody body = resenvelope.getBody();

            Iterator children = body.getChildren();
            while (children != null && children.hasNext()) {
                OMNode child = (OMNode) children.next();
                if (child.getType() == OMNode.ELEMENT_NODE) {
                    OMElement element = (OMElement) child;
                    OMNamespace ns = element.getNamespace();
                    if (OMConstants.SOAPFAULT_LOCAL_NAME.equals(element.getLocalName())
                            && OMConstants.SOAPFAULT_NAMESPACE_URI.equals(ns.getName())) {
                        Iterator it = element.getChildren();
                        String error = null;
                        while (it.hasNext()) {
                            OMNode node = (OMNode) it.next();
                            if (OMNode.TEXT_NODE == node.getType()) {
                                error = ((OMText) node).getValue();
                                if (error != null) {
                                    break;
                                }
                            }
                        }
                        throw new AxisFault(error);
                    }
                }
            }
            return resenvelope;
        } catch (OMException e) {
            throw AxisFault.makeFault(e);
        } catch (IOException e) {
            throw AxisFault.makeFault(e);
        }
    }

    public void sendReceiveAsync(SOAPEnvelope envelope, CallBack callback){
      //todo implement this
    }

    private MessageContext createIncomingMessageContext(InputStream in, AxisEngine engine) throws AxisFault {
        MessageContext msgContext;
        try {
            msgContext = new MessageContext(engine.getRegistry());
            InputStreamReader isr = new InputStreamReader(in);
            XMLStreamReader reader = XMLInputFactory.newInstance().createXMLStreamReader(isr);
            StAXBuilder builder = new StAXSOAPModelBuilder(OMFactory.newInstance(), reader);
            msgContext.setEnvelope((SOAPEnvelope) builder.getDocumentElement());
        } catch (XMLStreamException e) {
            throw AxisFault.makeFault(e);
        }
        return msgContext;

    }

}