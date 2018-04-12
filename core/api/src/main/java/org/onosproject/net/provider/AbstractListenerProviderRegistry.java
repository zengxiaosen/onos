/*
 * Copyright 2015-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.net.provider;


import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onosproject.event.Event;
import org.onosproject.event.EventDeliveryService;
import org.onosproject.event.EventListener;
import org.onosproject.event.ListenerRegistry;
import org.onosproject.event.ListenerService;

/**
 * Basis for components which need to export listener mechanism.
 * 监听器机制需要导出的基础组件,onos事件驱动的基础,Manager需要继承的模板
 */
@Component
public abstract class AbstractListenerProviderRegistry<E extends Event, L extends EventListener<E>,
                                                       P extends Provider, S extends ProviderService<P>>
        extends AbstractProviderRegistry<P, S> implements ListenerService<E, L> {

    // If only Java supported mixins...

    protected final ListenerRegistry<E, L> listenerRegistry = new ListenerRegistry<>();

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected EventDeliveryService eventDispatcher;

    @Override
    public void addListener(L listener) {
        listenerRegistry.addListener(listener);
    }

    @Override
    public void removeListener(L listener) {
        listenerRegistry.removeListener(listener);
    }


    /**
     * Safely posts the specified event to the local event dispatcher.
     * If there is no event dispatcher or if the event is null, this method
     * is a noop.
     * 将指定的事件安全地发布到本地事件分派器。 如果没有事件调度程序或事件为空，则此方法为noop(空操作)
     *
     * @param event event to be posted; may be null
     */
    protected void post(E event) {
        if (event != null && eventDispatcher != null) {
            eventDispatcher.post(event);
        }
    }

}
