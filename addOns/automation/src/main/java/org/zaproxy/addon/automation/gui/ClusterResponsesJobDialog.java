/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.automation.gui;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.HhMmSs;
import org.zaproxy.addon.automation.jobs.ClusterResponsesJob;
import org.zaproxy.addon.automation.jobs.DelayJob;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

import java.text.ParseException;

@SuppressWarnings("serial")
public class ClusterResponsesJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.clusterResponses.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String RESPONSE_LENGTH_PARAM = "automation.dialog.clusterResponses.responseLength";
    private static final String REQUEST_LENGTH_PARAM = "automation.dialog.clusterResponses.requestLength";
    private static final String RESPONSE_TIME_PARAM = "automation.dialog.clusterResponses.responseTime";
    private static final String REFLECTED_PARAM = "automation.dialog.clusterResponses.reflected";

    private ClusterResponsesJob job;

    public ClusterResponsesJobDialog(ClusterResponsesJob job) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(300, 200));
        this.job = job;

        this.addTextField(NAME_PARAM, this.job.getData().getName());
        this.addTextField(RESPONSE_LENGTH_PARAM, this.job.getData().getParameters().getResponseLengthWeight());
        this.addTextField(REQUEST_LENGTH_PARAM, this.job.getData().getParameters().getRequestLengthWeight());
        this.addTextField(RESPONSE_TIME_PARAM, this.job.getData().getParameters().getResponseTimeWeight());
        this.addTextField(REFLECTED_PARAM, this.job.getData().getParameters().getReflectedWeight());
        this.addPadding();
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setResponseLengthWeight(this.getStringValue(RESPONSE_LENGTH_PARAM));
        this.job.getParameters().setRequestLengthWeight(this.getStringValue(REQUEST_LENGTH_PARAM));
        this.job.getParameters().setResponseTimeWeight(this.getStringValue(RESPONSE_TIME_PARAM));
        this.job.getParameters().setReflectedWeight(this.getStringValue(REFLECTED_PARAM));
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        try {
            Double.valueOf(this.getStringValue(RESPONSE_LENGTH_PARAM));
            Double.valueOf(this.getStringValue(REQUEST_LENGTH_PARAM));
            Double.valueOf(this.getStringValue(RESPONSE_TIME_PARAM));
            Double.valueOf(this.getStringValue(REFLECTED_PARAM));
        } catch (NumberFormatException e) {
            return Constant.messages.getString("automation.dialog.clusterResponses.error.nan");
        }
        return null;
    }
}
