/*! grafana - v4.1.0-1481060956pre1 - 2016-12-06
 * Copyright (c) 2016 Torkel Ödegaard; Licensed Apache-2.0 */

System.register(["app/core/config","jquery","lodash","app/core/utils/kbn","./panel_ctrl","app/core/utils/rangeutil","app/core/utils/datemath"],function(a){var b,c,d,e,f,g,h,i,j=this&&this.__extends||function(a,b){function c(){this.constructor=a}for(var d in b)b.hasOwnProperty(d)&&(a[d]=b[d]);a.prototype=null===b?Object.create(b):(c.prototype=b.prototype,new c)};return{setters:[function(a){b=a},function(a){c=a},function(a){d=a},function(a){e=a},function(a){f=a},function(a){g=a},function(a){h=a}],execute:function(){i=function(a){function f(b,c){a.call(this,b,c),this.editorTabIndex=1,this.$q=c.get("$q"),this.datasourceSrv=c.get("datasourceSrv"),this.timeSrv=c.get("timeSrv"),this.templateSrv=c.get("templateSrv"),this.panel.targets||(this.panel.targets=[{}]),this.events.on("refresh",this.onMetricsPanelRefresh.bind(this)),this.events.on("init-edit-mode",this.onInitMetricsPanelEditMode.bind(this))}return j(f,a),f.prototype.onInitMetricsPanelEditMode=function(){this.addEditorTab("Metrics","public/app/partials/metrics.html"),this.addEditorTab("Time range","public/app/features/panel/partials/panelTime.html")},f.prototype.onMetricsPanelRefresh=function(){var a=this;if(!this.otherPanelInFullscreenMode()){if(this.panel.snapshotData){this.updateTimeRange();var b=this.panel.snapshotData;return d["default"].isArray(b)||(b=b.data),void this.events.emit("data-snapshot-load",b)}this.dataStream||(delete this.error,this.loading=!0,this.updateTimeRange(),this.setTimeQueryStart(),this.datasourceSrv.get(this.panel.datasource).then(this.issueQueries.bind(this)).then(this.handleQueryResult.bind(this))["catch"](function(b){return b.cancelled?void console.log("Panel request cancelled",b):(a.loading=!1,a.error=b.message||"Request Error",a.inspector={error:b},a.events.emit("data-error",b),void console.log("Panel data error:",b))}))}},f.prototype.setTimeQueryStart=function(){this.timing.queryStart=(new Date).getTime()},f.prototype.setTimeQueryEnd=function(){this.timing.queryEnd=(new Date).getTime()},f.prototype.updateTimeRange=function(){this.range=this.timeSrv.timeRange(),this.rangeRaw=this.range.raw,this.applyPanelTimeOverrides(),this.panel.maxDataPoints?this.resolution=this.panel.maxDataPoints:this.resolution=Math.ceil(c["default"](window).width()*(this.panel.span/12)),this.calculateInterval()},f.prototype.calculateInterval=function(){var a=this.panel.interval;a?a=this.templateSrv.replace(a,this.panel.scopedVars):this.datasource&&this.datasource.interval&&(a=this.datasource.interval);var b=e["default"].calculateInterval(this.range,this.resolution,a);this.interval=b.interval,this.intervalMs=b.intervalMs},f.prototype.applyPanelTimeOverrides=function(){if(this.timeInfo="",this.panel.timeFrom){var a=this.templateSrv.replace(this.panel.timeFrom,this.panel.scopedVars),b=g.describeTextRange(a);if(b.invalid)return void(this.timeInfo="invalid time override");if(d["default"].isString(this.rangeRaw.from)){var c=h.parse(b.from);this.timeInfo=b.display,this.rangeRaw.from=b.from,this.rangeRaw.to=b.to,this.range.from=c,this.range.to=h.parse(b.to)}}if(this.panel.timeShift){var e=this.templateSrv.replace(this.panel.timeShift,this.panel.scopedVars),f=g.describeTextRange(e);if(f.invalid)return void(this.timeInfo="invalid timeshift");var i="-"+e;this.timeInfo+=" timeshift "+i,this.range.from=h.parseDateMath(i,this.range.from,!1),this.range.to=h.parseDateMath(i,this.range.to,!0),this.rangeRaw=this.range}this.panel.hideTimeOverride&&(this.timeInfo="")},f.prototype.issueQueries=function(a){if(this.datasource=a,!this.panel.targets||0===this.panel.targets.length)return this.$q.when([]);for(var b=[],c=0;c<this.panel.targets.length;c++)this.panel.targets[c].maxValueDtOnly||b.push(this.panel.targets[c]);if(!b||0===b.length)return this.$q.when([]);var d={panelId:this.panel.id,range:this.range,rangeRaw:this.rangeRaw,interval:this.interval,intervalMs:this.intervalMs,targets:b,format:"png"===this.panel.renderer?"png":"json",maxDataPoints:this.resolution,scopedVars:this.panel.scopedVars,cacheTimeout:this.panel.cacheTimeout};return a.query(d)},f.prototype.handleQueryResult=function(a){return this.setTimeQueryEnd(),this.loading=!1,a&&a.subscribe?void this.handleDataStream(a):(this.dashboard.snapshot&&(this.panel.snapshotData=a.data),a&&a.data||(console.log("Data source query result invalid, missing data field:",a),a={data:[]}),this.events.emit("data-received",a.data))},f.prototype.handleDataStream=function(a){var b=this;return this.dataStream?void console.log("two stream observables!"):(this.dataStream=a,void(this.dataSubscription=a.subscribe({next:function(a){console.log("dataSubject next!"),a.range&&(b.range=a.range),b.events.emit("data-received",a.data)},error:function(a){b.events.emit("data-error",a),console.log("panel: observer got error")},complete:function(){console.log("panel: observer got complete"),b.dataStream=null}})))},f.prototype.setDatasource=function(a){var c=this;a.meta.mixed?d["default"].each(this.panel.targets,function(a){a.datasource=c.panel.datasource,a.datasource||(a.datasource=b["default"].defaultDatasource)}):this.datasource&&this.datasource.meta.mixed&&d["default"].each(this.panel.targets,function(a){delete a.datasource}),this.panel.datasource=a.value,this.datasourceName=a.name,this.datasource=null,this.refresh()},f}(f.PanelCtrl),a("MetricsPanelCtrl",i)}}});
