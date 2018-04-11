/*
 * Copyright 2014-present Open Networking Foundation
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
package org.onosproject.event;

import java.util.Set;

/**
 * Abstraction of an event sink registry capable of tracking sinks based on
 * their event class.
 * 基于事件的类别的,事件追踪器注册抽象
 */
public interface EventSinkRegistry {

    /**
     * Adds the specified sink for the given event class.
     * 给指定的事件类添加特定的追踪器
     *
     * @param eventClass event class
     * @param sink       event sink
     * @param <E>        type of event
     */
    <E extends Event> void addSink(Class<E> eventClass, EventSink<E> sink);

    /**
     * Removes the sink associated with the given event class.
     *
     * @param eventClass event class
     * @param <E>        type of event
     */
    <E extends Event> void removeSink(Class<E> eventClass);

    /**
     * Returns the event sink associated with the specified event class.
     * 返回特定事件类的事件追踪器
     *
     * @param eventClass event class
     * @param <E>        type of event
     * @return event sink or null if none found
     */
    <E extends Event> EventSink<E> getSink(Class<E> eventClass);

    /**
     * Returns the set of all event classes for which sinks are presently
     * registered.
     * 返回追踪器当前注册的事件类
     *
     * @return set of event classes
     */
    Set<Class<? extends Event>> getSinks();

}
