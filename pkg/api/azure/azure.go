package azure

import (

  "github.com/grafana/grafana/pkg/middleware"
  m "github.com/grafana/grafana/pkg/models"
  "github.com/grafana/grafana/pkg/log"
  "io/ioutil"
  "encoding/json"
  "errors"
  "net/http"
  "bytes"
  "time"
  "strconv"
  "sync"
  "net/url"
  "sort"

)
var (
  dataproxyLogger log.Logger = log.New("azure-log")
)

type cwRequest struct {
  Action     string `json:"action"`
  Body       []byte `json:"-"`
  Headers    map[string][]string
  DataSource *m.DataSource
}

type MarginalSingleData struct {
  Datapoints [][2]float64 `json:"datapoints"`
  Target string `json:"target"`
  Average float64 `json:"average"`
}

type SingleData struct {
  Datapoints [][2]float64 `json:"datapoints"`
  Target string `json:"target"`
}

type AllData []MarginalSingleData

type AuthTokenInfo struct {

  TokenType string `json:"token_type"`
  ExpiresIn string `json:"expires_in"`
  ExpiresOn string `json:"expires_on"`
  NotBefore string `json:"not_before"`
  Resource string `json:"resource"`
  AccessToken string `json:"access_token"`
}

type GenStatus struct {

  Code int `json:"code"`
  Message string `json:"message"`
  Error error `json:"error"`
  AuthTokenInf AuthTokenInfo `json:"tokenInfo"`
}

type TableInfo struct{

  EndTime string `json:"endTime"`
  SasToken string `json:"sasToken"`
  SasTokenExpirationTime string `json:"sasTokenExpirationTime"`
  StartTime string `json:"startTime"`
  TableName string `json:"tableName"`
}

type Location struct{

  TableEndpoint string `json:"tableEndpoint"`
  TableInfo []TableInfo `json:"tableInfo"`
  PartitionKey string `json:"partitionKey"`
}

type MetricAvailabilities struct {

  TimeGrain string `json:"timeGrain"`
  Location Location `json:"location"`
}

type Name struct {

  Value string `json:"value"`
  LocalizedValue string `json:"localizedValue"`
}

type Value struct {

  Name Name `json:"name"`
  MetricAvailabilities []MetricAvailabilities `json:"metricAvailabilities"`
  Id string `json:"id"`
}

type MetricDefinitions struct {

  Value []Value `json:"value"`
}

var accessTokensCache = make(map[int64]AuthTokenInfo)
var credentialCacheLock sync.RWMutex
type actionHandler func(*cwRequest, *middleware.Context)
var actionHandlers map[string]actionHandler
var savedTokensLegacyQuery = make(map[string]MetricDefinitions)


func init() {
  actionHandlers = map[string]actionHandler{
    "GenAuthToken":         handleGenAuthToken,
    "DefaultQueryMetrics":  handleDefaultQueryMetrics,
    "DefaultQuery":         handleDefaultQuery,
    "MarginalQuery":        handleMarginalQuery,
    "LegacyQuery":          handleLegacyQuery,
  }
}

func getAndSaveAuthTokenInfo(req *cwRequest)(AuthTokenInfo, error)  {
  id := req.DataSource.Id
  credentialCacheLock.RLock()
  if _, ok := accessTokensCache[id]; ok{
    if isInBetweenTime(accessTokensCache[id].NotBefore,accessTokensCache[id].ExpiresOn) && (accessTokensCache[id].AccessToken != ""){
      credentialCacheLock.RUnlock()
      return accessTokensCache[id],nil
    }
  }
  status := genAuthToken(req)
  if status.Code == 200 {
    accessTokensCache[id] = status.AuthTokenInf
    credentialCacheLock.RUnlock()
    return accessTokensCache[id], nil
  }
  credentialCacheLock.RUnlock()
  return AuthTokenInfo{}, status.Error
}

func execDefaultQueryReturnBodyBytes(token string, url string) ([]byte,string){
  client := &http.Client{Timeout: 20 * time.Second}
  requ, erra := http.NewRequest("GET", url, nil)
  if erra != nil {
    return nil,erra.Error()
  }
  requ.Header.Add("Content-Type", "application/json")
  requ.Header.Add("Authorization", "Bearer " + token)
  resp, errb := client.Do(requ)
  if errb != nil {
    return nil, errb.Error()
  }
  defer resp.Body.Close()
  bodyBytes, err2 := ioutil.ReadAll(resp.Body)
  if err2 != nil {
    return nil,err2.Error()
  }

  return bodyBytes,""
}

func execDefaultQuery(token string, url string) (map[string]interface {},string){
  client := &http.Client{Timeout: 20 * time.Second}
  requ, erra := http.NewRequest("GET", url, nil)
  if erra != nil {
    return nil,erra.Error()
  }

  requ.Header.Add("Content-Type", "application/json")
  requ.Header.Add("Authorization", "Bearer " + token)
  resp, errb := client.Do(requ)
  if errb != nil {
    return nil, "Error reaching "+url
  }
  defer resp.Body.Close()
  bodyBytes, err2 := ioutil.ReadAll(resp.Body)
  if err2 != nil {
    return nil,err2.Error()
  }

  if resp.StatusCode > 299{
    return nil,resp.Status
  }
  var data map[string]interface{}
  err := json.Unmarshal([]byte(bodyBytes), &data)
  if err != nil {
    return nil,err.Error()
  }
  return data,""
}

func genAuthToken(req *cwRequest) GenStatus{

  var bodyJson AuthTokenInfo;
  client := &http.Client{Timeout: 20 * time.Second}
  clientsecret := req.DataSource.SecureJsonData.Decrypt()["clientsecret"]
  tenantId := req.DataSource.JsonData.Get("tenantid").MustString()
  clientId := req.DataSource.JsonData.Get("clientid").MustString()


  resource := "https://management.azure.com/"
  loginurl := "https://login.microsoftonline.com/"+tenantId+"/oauth2/token"
  body := "grant_type=client_credentials&resource="+resource+"&client_id="+clientId+"&client_secret="+clientsecret

  requ, erra := http.NewRequest("POST", loginurl, bytes.NewBufferString(body))
  if erra != nil {
   status := GenStatus{Code:500,Message:"Unable to generate request",Error:erra}
    return status
  }
  requ.Header.Add("Content-Type", "application/x-www-form-urlencoded")
  resp, errb := client.Do(requ)
  if errb != nil {
    status := GenStatus{Code:500,Message:"Unable to contact azure service",Error:errb}
    return status
  }
  defer resp.Body.Close()

  erre :=  json.NewDecoder(resp.Body).Decode(&bodyJson)
  if erre != nil {
    status := GenStatus{Code:500,Message:"Error decoding response",Error:erre}
    return status
  }

  if isInBetweenTime(bodyJson.NotBefore,bodyJson.ExpiresOn){
    status := GenStatus{Code:200,Message:"Ok",AuthTokenInf:bodyJson}
    return status
  }else {
    status := GenStatus{Code:500,Message:"Token returned it's not valid, please check credentials",Error:errors.New("Token returned it's not valid")}
     return status
  }

}

func handleDefaultQueryMetrics(req *cwRequest, c *middleware.Context){

  token,error := getAndSaveAuthTokenInfo(req)

  if error != nil {
    dataproxyLogger.Error("Error while obtaining token")
    c.JsonApiErr(500,"Error obtaining access token", error)
    return
  }

  query := req.Headers["Query"][0]
  data,error2 := execDefaultQuery(token.AccessToken,query)
  if error2 != "" {
    dataproxyLogger.Error("Error calling query")
    c.JsonApiErr(500, error2,errors.New(error2))
    return
  }

  entityMetricValue := data["value"].([]interface{})[0].(map[string]interface {})
  entityMetricData := entityMetricValue["data"].([]interface{})
  datapoints := [][2]float64{}
  //for each pair of metric,timestamp
  for _, valueTimestampPair := range entityMetricData {
    valueTimestampMap := valueTimestampPair.(map[string]interface{})
    keys := Keys(valueTimestampMap)
    var datapoint [2]float64
    if(len(keys) >1){
      for _, item := range keys{
        key := item.(string)
        if(key == "timeStamp"){
          parsedTime,_ := time.Parse(time.RFC3339,valueTimestampMap[key].(string))
          datapoint[1] = float64(parsedTime.UnixNano() / 1000000)
        }else{
          valu := valueTimestampMap[key].(float64)
          datapoint[0] = valu
        }
      }
    }else {
      parsedTime,_ := time.Parse(time.RFC3339,valueTimestampMap["timeStamp"].(string))
      datapoint[1] = float64(parsedTime.UnixNano() / 1000000)
      datapoint[0] = 0
    }
    datapoints = append(datapoints,datapoint)
  }
  sdMetrics :=SingleData{Datapoints:datapoints,Target:req.Headers["Target"][0]}
  sort.Sort(sdMetrics)
  c.JSON(200,sdMetrics)
  return
}

func handleDefaultQuery(req *cwRequest, c *middleware.Context){

  token,error := getAndSaveAuthTokenInfo(req)

  if error != nil {
    dataproxyLogger.Error("Error while obtaining token")
    c.JsonApiErr(500,"Error obtaining access token", error)
    return
  }

  query := req.Headers["Query"][0]
  data,error2 := execDefaultQuery(token.AccessToken,query)
  if error2 != "" {
    dataproxyLogger.Error("Error calling query")
    c.JsonApiErr(500, error2,errors.New(error2))
    return
  }
  c.JSON(200,data)
  return
}

func Keys(m map[string]interface{}) []interface{} {
keys := make([]interface{}, len(m))
i := 0
for k := range m {
keys[i] = k
i++
}
return keys
}

func (sd AllData) Len() int{

  return len(sd)
}

func (sd AllData) Less(i,j int) bool{

  return sd[i].Average < sd[j].Average
}

func (sd AllData) Swap(i,j int){
  sd[i],sd[j] = sd[j],sd[i]
}

func (sd SingleData) Len()int{

  return len(sd.Datapoints)
}
func (sd SingleData) Less(i,j int) bool{
  return sd.Datapoints[i][1] < sd.Datapoints[j][1]
}
func (sd SingleData) Swap(i,j int){
  sd.Datapoints[i],sd.Datapoints[j] = sd.Datapoints[j],sd.Datapoints[i]
}


func isMainInfoValid(md MetricDefinitions)bool{
  if(md.Value == nil){
    dataproxyLogger.Debug("No metric definition in cache")
    return false
  }
  expirationTime,_ := time.Parse(time.RFC3339, md.Value[0].MetricAvailabilities[0].Location.TableInfo[0].SasTokenExpirationTime)
  return expirationTime.After(time.Now())
}

func handleLegacyQuery(req *cwRequest, c *middleware.Context) {

  tokenInfo := savedTokensLegacyQuery[req.Headers["Id"][0]]
  if (!isMainInfoValid(tokenInfo)) {
    token, error := getAndSaveAuthTokenInfo(req)
    if error != nil {
      dataproxyLogger.Error("Error while obtaining token")
      c.JsonApiErr(500, "Error obtaining access token", error)
      return
    }
    filter := url.QueryEscape("name.value eq '" + req.Headers["Value"][0] + "'")
    url := req.Headers["Resource"][0] + req.Headers["Uri"][0] + "/metricDefinitions?api-version=2014-04-01&$filter=" + filter
    metricDefinitions, error2 := execDefaultQueryReturnBodyBytes(token.AccessToken, url)
    if error2 != "" {
      dataproxyLogger.Error("Error calling query")
      c.JsonApiErr(500, error2, errors.New(error2))
      return
    }
    var bodyJson MetricDefinitions;
    erre := json.Unmarshal(metricDefinitions, &bodyJson)
    if erre != nil {
      c.JsonApiErr(500, "Error decoding response", erre)
      return
    }

    responses,errormfd := getMetricsFromMetricDefinitions(bodyJson, req.Headers["From"][0], req.Headers["Till"][0])
    if(errormfd!=""){
      c.JsonApiErr(500,errormfd, errors.New(errormfd))
      return
    }

    sdmetrics,errorMetrics :=  metricsFromLegacyHandler(responses,req.Headers["From"][0], req.Headers["Till"][0],req.Headers["Target"][0])
    if(errorMetrics != ""){
      c.JsonApiErr(500,errorMetrics, errors.New(errorMetrics))
      return
    }
    savedTokensLegacyQuery[req.Headers["Id"][0]] = bodyJson
    c.JSON(200, sdmetrics)
    return
  }else{
    responses,errormfd := getMetricsFromMetricDefinitions(tokenInfo, req.Headers["From"][0], req.Headers["Till"][0])
    if(errormfd!=""){
      c.JsonApiErr(500,errormfd, errors.New(errormfd))
      return
    }
   sdmetrics,errorMetrics :=  metricsFromLegacyHandler(responses,req.Headers["From"][0], req.Headers["Till"][0],req.Headers["Target"][0])
    if(errorMetrics != ""){
      c.JsonApiErr(500,errorMetrics, errors.New(errorMetrics))
      return
    }
    c.JSON(200, sdmetrics)
    return
  }
}

func metricsFromLegacyHandler(response []map[string]interface{}, timefrom string, timetill string,target string) (SingleData,string){

     datapoints := [][2]float64{}
    for _,values := range response{
      value := values["value"].([]interface{})
      for _,entries := range value{
        parsedTime,_:= time.Parse(time.RFC3339,entries.(map[string]interface{})["Timestamp"].(string))
        fromDate,error1 := time.Parse(time.RFC3339, timefrom)
        if(error1!=nil){
          return SingleData{},error1.Error()
        }
        toDate,error2 := time.Parse(time.RFC3339, timetill)
        if(error2!=nil){
          return SingleData{},error2.Error()
        }
        if(parsedTime.After(fromDate) && parsedTime.Before(toDate)){
          var datapoint [2]float64
          datapoint[0] = entries.(map[string]interface{})["Average"].(float64)
          datapoint[1] = float64(parsedTime.UnixNano() / 1000000)
          datapoints = append(datapoints,datapoint)
        }
      }
    }
    sdMetrics :=SingleData{Datapoints:datapoints,Target:target}

  sort.Sort(sdMetrics)

  return sdMetrics,""
}

func getMetricsFromMetricDefinitions(metricDefinitions MetricDefinitions, from string, till string) ([]map[string]interface{},string){

  fromDate,error1 := time.Parse(time.RFC3339, from)
  if(error1!=nil){
    return nil,error1.Error()
  }
  toDate,error2 := time.Parse(time.RFC3339, till)
  if(error2!=nil){
    return nil,error2.Error()
  }
  dif := toDate.Sub(fromDate)
  var timeGrain string
  if (dif > 25) {
    timeGrain = "PT1H";
  }else {
    timeGrain = "PT1M";
  }
  responses,errorMetrics := getMetrics(metricDefinitions,from,till,timeGrain)
  if(errorMetrics!=""){
    return nil,errorMetrics
  }
  return responses,""
}

func getMetrics(metricDefinitions MetricDefinitions,from string, till string, timegrain string) ([]map[string]interface{},string){

  queries, error1 := generateLegacyQueries(metricDefinitions,from,till,timegrain)
  if(error1!=""){
    return nil,error1
  }
  var responses []map[string]interface{}
  for _,query := range queries{
    client := &http.Client{Timeout: 20 * time.Second}
    requ, erra := http.NewRequest("GET", query, nil)
    if erra != nil {
      dataproxyLogger.Error("Error generating new get request for: "+query)
      return responses,erra.Error()
    }
    requ.Header.Add("Accept", "application/json;odata=nometadata")
    resp, errb := client.Do(requ)
    if errb != nil {
      dataproxyLogger.Error("Error generating new get request for: "+query)
      return nil,errb.Error()
    }

    defer resp.Body.Close()
    bodyBytes, err2 := ioutil.ReadAll(resp.Body)
    if err2 != nil {
      return nil, "Error reading response from server"
    }

    if resp.StatusCode > 299{
      return nil, "Error returned from server with message: "+resp.Status
    }
    var data map[string]interface{}
    err := json.Unmarshal([]byte(bodyBytes), &data)
    if err != nil {
      return nil,err.Error()
    }else{
      responses = append(responses,data)
    }
  }
    return responses,""
}

func generateLegacyQueries(mds MetricDefinitions, timeFrom string, timeTill string, timegrain string) ([]string,string){

  value:=mds.Value[0]
  mas := getMetricAvailabilitiesByTimeGrain(value.MetricAvailabilities,timegrain)
  if(mas.TimeGrain == ""){
    return nil,"No metrics available for any timegrain"
  }
  tableInfos :=mas.Location.TableInfo
  from,error1 := time.Parse(time.RFC3339,timeFrom)
  if(error1!=nil){
    return nil,error1.Error()
  }
  till,error2 := time.Parse(time.RFC3339,timeTill)
  if(error2!=nil){
    return nil,error1.Error()
  }
  var queries []string
  for _,tableInfo := range tableInfos{
      tableInfoStatTime,error3 :=time.Parse(time.RFC3339,tableInfo.StartTime)
    if(error3!=nil){
      return nil,error1.Error()
    }
      tableInfoEndTime,error4 :=time.Parse(time.RFC3339,tableInfo.EndTime)
    if(error4!=nil){
      return nil,error4.Error()
    }
    if(!(tableInfoStatTime.Before(from) && tableInfoEndTime.Before(from)) && !(tableInfoStatTime.After(till) && tableInfoEndTime.After(till))){
      query :=makeQuery(mas.Location.PartitionKey,value.Name.Value,mas.Location.TableEndpoint,tableInfo)
      queries = append(queries,query)
    }
  }
  return queries,""
}

func makeQuery(partionKey string, countername string, tableend string, tableinfo TableInfo) string{
  filter := url.QueryEscape("(PartitionKey eq '"+partionKey+"' and CounterName eq '"+countername+"')")
  return tableend+tableinfo.TableName+tableinfo.SasToken+"&$filter="+filter
}

func getMetricAvailabilitiesByTimeGrain(ma []MetricAvailabilities, timegrain string) MetricAvailabilities{

  for _, singleMA := range ma {
    if(string(singleMA.TimeGrain) == string(timegrain)){
      return singleMA
    }
  }
  if(len(ma)>0){
return ma[0]
}
  return  MetricAvailabilities{}
}

func handleMarginalQuery(req *cwRequest, c *middleware.Context){

  token,error := getAndSaveAuthTokenInfo(req)
  if error != nil {
    dataproxyLogger.Error("Error while obtaining token")
    c.JsonApiErr(500,"Error obtaining access token", error)
    return
  }
  query := req.Headers["Query"][0]
  //gets all the entities (vms) in the respective resource
  entitiesArray,error2 := execDefaultQuery(token.AccessToken,query)
  if error2 != "" {
    dataproxyLogger.Error("Error calling query")
    c.JsonApiErr(500, error2,errors.New(error2))
    return
  }

  //gets time diference in days to choose granularity
  from,_ := time.Parse(time.RFC3339, req.Headers["From"][0])
  to,_ := time.Parse(time.RFC3339,req.Headers["To"][0])
  dif := to.Sub(from)
  var timeGrain string
  if (dif > 25) {
    timeGrain = "'PT1H'";
  }else {
    timeGrain = "'PT1M'";
  }

  metric := req.Headers["Filtertopmetric"][0]
  filter := "(name.value eq '" + metric + "') and timeGrain eq duration" + timeGrain + " and startTime eq " + req.Headers["From"][0] + " and endTime eq " + req.Headers["To"][0];

  entitiesArrayCast :=entitiesArray["value"].([]interface{})
  //for each entity it will call its metric data for the given time interval
  allDataPoints := AllData{}
  for _, num := range entitiesArrayCast {
    entityInfo :=num.(map[string]interface {})
    urll := "https://management.azure.com" + entityInfo["id"].(string)+ "/providers/microsoft.insights/metrics?api-version=2016-09-01&$filter=" + url.QueryEscape(filter)

    entityMetricRaw,error3 := execDefaultQuery(token.AccessToken,urll)
    if error3 != "" {
      dataproxyLogger.Error("Error calling query")
      c.JsonApiErr(500, error3,errors.New(error3))
      return
    }
    entityMetricValue := entityMetricRaw["value"].([]interface{})[0].(map[string]interface {})
    entityMetricData := entityMetricValue["data"].([]interface{})
    datapoints := [][2]float64{}
    var average float64
    //for each pair of metric,timestamp
    for _, valueTimestampPair := range entityMetricData {
      valueTimestampMap := valueTimestampPair.(map[string]interface{})
      keys := Keys(valueTimestampMap)
      var datapoint [2]float64
      if(len(keys) >1){
        for _, item := range keys{

          key := item.(string)
          if(key == "timeStamp"){
            parsedTime,_ := time.Parse(time.RFC3339,valueTimestampMap[key].(string))
            datapoint[1] = float64(parsedTime.UnixNano() / 1000000)
          }else{
            valu := valueTimestampMap[key].(float64)
            datapoint[0] = valu
            average = average+valu
          }
        }
      }else {
        parsedTime,_ := time.Parse(time.RFC3339,valueTimestampMap["timeStamp"].(string))
        datapoint[1] = float64(parsedTime.UnixNano() / 1000000)
        datapoint[0] = 0
      }
      datapoints = append(datapoints,datapoint)
    }
    average = average/float64(len(entityMetricData))

    targetString := ""
    if(req.Headers["Targetentityname"][0] == "true"){
      targetString = entityInfo["name"].(string)
    }
    if(req.Headers["Targetmetricname"][0] == "true"){
      if(len(targetString)>0){
        targetString = targetString+" - "
      }
      targetString = targetString+"Top "+metric
    }
    if(req.Headers["Targetunit"][0] == "true"){
      if(len(targetString)>0){
        targetString = targetString+" - "
      }

      targetString = targetString+ entityMetricValue["unit"].(string);
    }

    //adding target to metrics of each entity result
    entityMetricRaw["target"] = targetString
    df := MarginalSingleData{Datapoints:datapoints,Target:targetString,Average:average}
    allDataPoints = append(allDataPoints,df)
  }
  limit,_ :=strconv.Atoi(req.Headers["Limit"][0])

  totalsdMetrics :=[]SingleData{}
  if(limit < len(allDataPoints)){
    sort.Sort(allDataPoints)
    if(req.Headers["Metrictype"][0] == "bottom") {
      allCuted := allDataPoints[:limit]
      dataproxyLogger.Debug("top query finished")
      for _,dtps := range allCuted{
        sdMetrics := SingleData{Datapoints:dtps.Datapoints,Target:dtps.Target}
        sort.Sort(sdMetrics)
        totalsdMetrics =append(totalsdMetrics,sdMetrics)
      }
      c.JSON(200, totalsdMetrics)
      return
    } else{
      start := len(allDataPoints)-limit
      allCuted := allDataPoints[start:]
      dataproxyLogger.Debug("top query finished")
      for _,dtps := range allCuted{
        sdMetrics := SingleData{Datapoints:dtps.Datapoints,Target:dtps.Target}
        sort.Sort(sdMetrics)
        totalsdMetrics =append(totalsdMetrics,sdMetrics)
      }
      c.JSON(200, totalsdMetrics)
      return
    }
  }
  for _,dtps := range allDataPoints{
    sdMetrics := SingleData{Datapoints:dtps.Datapoints,Target:dtps.Target}
    sort.Sort(sdMetrics)
    totalsdMetrics =append(totalsdMetrics,sdMetrics)
  }
  dataproxyLogger.Debug("top query finished")
  c.JSON(200,totalsdMetrics)
  return
}

func handleGenAuthToken(req *cwRequest, c *middleware.Context){

  var status GenStatus = genAuthToken(req)
  if status.Code == 200 {
    accessTokensCache[req.DataSource.Id] = status.AuthTokenInf
    c.JSON(200, status.AuthTokenInf)
  }  else{
    c.JsonApiErr(status.Code,status.Message,status.Error)
}
return
}

func isInBetweenTime(older string, younger string) bool {

  olderTime, err := strconv.ParseInt(older, 10, 64)
  if err != nil {
    dataproxyLogger.Error("Error converting older time: "+older)
    return false
  }

  youngerTime, err := strconv.ParseInt(younger, 10, 64)
  if err != nil {
    dataproxyLogger.Error("Error converting younger time: "+younger)
    return false
  }
  timeNow := time.Now().Unix()

  if timeNow < olderTime{
    dataproxyLogger.Debug("Time now is previous to older time")
    return false
  }
  if timeNow > youngerTime{
    dataproxyLogger.Debug("Time now is after younger time")
    return false
  }
  dataproxyLogger.Debug("Time now is in between")
    return true
}

func HandleRequest(c *middleware.Context, ds *m.DataSource) {
  var req cwRequest
  req.Body, _ = ioutil.ReadAll(c.Req.Request.Body)
  req.DataSource = ds
  req.Headers = c.Req.Request.Header
  json.Unmarshal(req.Body, &req)

  if handler, found := actionHandlers[req.Action]; !found {
    c.JsonApiErr(500, "Unexpected Azure Action", errors.New(req.Action))
    return
  } else {
    handler(&req, c)
  }
}
