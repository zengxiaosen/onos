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
package org.onosproject.net.config;


import com.google.common.annotations.Beta;

/**
 * Base abstract factory for creating configurations for the specified subject type.
 * 基础抽象工厂，用于为指定的主题类型创建配置。
 * @param <S> type of subject
 * @param <C> type of configuration
 */
@Beta
public abstract class ConfigFactory<S, C extends Config<S>> {

    private final SubjectFactory<S> subjectFactory;
    private final Class<C> configClass;
    private final String configKey;
    private final boolean isList;

    /**
     * Creates a new configuration factory for the specified class of subjects
     * capable of generating the configurations of the specified class. The
     * subject and configuration class keys are used merely as keys for use in
     * composite JSON trees.
     * 为能够生成指定类的配置的指定类别的主题创建新的配置工厂。
     * 主题和配置类键仅用作复合JSON树中的键。
     *
     * @param subjectFactory subject factory
     * @param configClass    configuration class
     * @param configKey      configuration class key
     */
    protected ConfigFactory(SubjectFactory<S> subjectFactory,
                            Class<C> configClass, String configKey) {
        this(subjectFactory, configClass, configKey, false);
    }

    /**
     * Creates a new configuration factory for the specified class of subjects
     * capable of generating the configurations of the specified class. The
     * subject and configuration class keys are used merely as keys for use in
     * composite JSON trees.
     * <p>
     * Note that configurations backed by JSON array are not easily extensible
     * at the top-level as they are inherently limited to holding an ordered
     * list of items.
     * </p>
     *
     * @param subjectFactory subject factory
     * @param configClass    configuration class
     * @param configKey      configuration class key
     * @param isList         true to indicate backing by JSON array
     */
    protected ConfigFactory(SubjectFactory<S> subjectFactory,
                            Class<C> configClass, String configKey,
                            boolean isList) {
        this.subjectFactory = subjectFactory;
        this.configClass = configClass;
        this.configKey = configKey;
        this.isList = isList;
    }

    /**
     * Returns the class of the subject to which this factory applies.
     *
     * @return subject type
     */
    public SubjectFactory<S> subjectFactory() {
        return subjectFactory;
    }

    /**
     * Returns the class of the configuration which this factory generates.
     *
     * @return configuration type
     */
    public Class<C> configClass() {
        return configClass;
    }

    /**
     * Returns the unique key (within subject class) of this configuration.
     * This is primarily aimed for use in composite JSON trees in external
     * representations and has no bearing on the internal behaviours.
     *
     * @return configuration key
     */
    public String configKey() {
        return configKey;
    }

    /**
     * Creates a new but uninitialized configuration. Framework will initialize
     * the configuration via {@link Config#init} method.
     *
     * @return new uninitialized configuration
     */
    public abstract C createConfig();

    /**
     * Indicates whether the configuration is a list and should be backed by
     * a JSON array rather than JSON object.
     *
     * @return true if backed by JSON array
     */
    public boolean isList() {
        return isList;
    }

}
