/*
 * Copyright 2001-2004 The Apache Software Foundation.
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
package org.apache.axis.ime.event;

import org.apache.axis.ime.MessageExchangeCorrelator;

/**
 * The MessageExchangeStatus event is used to provide status 
 * notifications to registered listeners.
 *
 * @author Ray Chun (rchun@sonicsoftware.com)
 */
public class MessageStatusEvent
        extends MessageCorrelatedEvent {

    protected MessageExchangeStatus status;
    
    public MessageStatusEvent(
            MessageExchangeCorrelator correlator,
            MessageExchangeStatus status) {
        super(correlator);
        this.status = status;
    }
    
    public MessageExchangeStatus getMessageExchangeStatus()
    {
        return status;
    }

}