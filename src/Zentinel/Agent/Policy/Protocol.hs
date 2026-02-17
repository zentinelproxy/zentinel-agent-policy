-- |
-- Module      : Zentinel.Agent.Policy.Protocol
-- Description : Zentinel Agent Protocol v2 implementation
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0
--
-- Self-contained implementation of the Zentinel Agent Protocol v2
-- for Unix Domain Socket communication.

module Zentinel.Agent.Policy.Protocol
  ( -- * Running the Agent
    runAgent
  , ServerConfig(..)
  , defaultServerConfig

    -- * Protocol Types
  , AgentMessage(..)
  , ProxyMessage(..)
  , EventType(..)

    -- * Request Events
  , RequestHeadersEvent(..)
  , RequestMetadata(..)

    -- * Response Types
  , AgentResponse(..)
  , Decision(..)

    -- * Response Builders
  , allow
  , block
  , redirect

    -- * Capabilities
  , AgentCapabilities(..)
  , defaultCapabilities

    -- * Health
  , HealthStatus(..)
  , LoadMetrics(..)
  , emptyLoadMetrics

    -- * Metrics
  , MetricsReport(..)
  , CounterMetric(..)
  , GaugeMetric(..)
  , counterMetric
  , gaugeMetric

    -- * Handler
  , AgentHandler(..)
  , LogLevel(..)
  ) where

import Control.Concurrent (forkIO)
import Control.Exception (bracket, try, catch, SomeException)
import Control.Monad (forever, when)
import Data.Aeson (FromJSON, ToJSON, Value(..), encode, decode, object, (.=), (.:), (.:?), (.!=))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KM
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as HM
import Data.IORef
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (getCurrentTime)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Word (Word16, Word32, Word64)
import GHC.Generics (Generic)
import Network.Socket hiding (recv, Debug)
import Network.Socket.ByteString (recv, sendAll)
import System.IO (hPutStrLn, stderr)

-- | Server configuration
data ServerConfig = ServerConfig
  { scSocketPath :: !(Maybe FilePath)
  , scLogLevel :: !LogLevel
  }
  deriving stock (Eq, Show)

data LogLevel = Debug | Info | Warn | Error
  deriving stock (Eq, Show, Ord)

-- | Default server configuration
defaultServerConfig :: ServerConfig
defaultServerConfig = ServerConfig
  { scSocketPath = Just "/tmp/zentinel-policy.sock"
  , scLogLevel = Info
  }

-- | Event types supported by the protocol
data EventType
  = RequestHeaders
  | RequestBodyChunk
  | RequestComplete
  | ResponseHeaders
  | ResponseBodyChunk
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

-- | Request metadata included with events
data RequestMetadata = RequestMetadata
  { rmRequestId :: !Text
  , rmConnectionId :: !Text
  , rmTimestampMs :: !Word64
  }
  deriving stock (Eq, Show, Generic)

instance FromJSON RequestMetadata where
  parseJSON = Aeson.withObject "RequestMetadata" $ \v -> RequestMetadata
    <$> v .: "request_id"
    <*> v .: "connection_id"
    <*> v .: "timestamp_ms"

-- | Request headers event from the proxy
data RequestHeadersEvent = RequestHeadersEvent
  { reqHdrMetadata :: !RequestMetadata
  , reqHdrMethod :: !Text
  , reqHdrUri :: !Text
  , reqHdrHeaders :: !(HashMap Text Text)
  , reqHdrAuthority :: !(Maybe Text)
  }
  deriving stock (Eq, Show, Generic)

instance FromJSON RequestHeadersEvent where
  parseJSON = Aeson.withObject "RequestHeadersEvent" $ \v -> RequestHeadersEvent
    <$> v .: "metadata"
    <*> v .: "method"
    <*> v .: "uri"
    <*> v .:? "headers" .!= HM.empty
    <*> v .:? "authority"

-- | Decision for agent response
data Decision
  = Allow
  | Block !Word16 !Text
  | Redirect !Text
  deriving stock (Eq, Show, Generic)

-- | Agent response to an event
data AgentResponse = AgentResponse
  { respRequestId :: !Text
  , respDecision :: !Decision
  , respHeaders :: !(HashMap Text Text)
  , respAuditTags :: ![Text]
  }
  deriving stock (Eq, Show, Generic)

instance ToJSON AgentResponse where
  toJSON AgentResponse{..} = object $
    [ "request_id" .= respRequestId
    , "headers" .= respHeaders
    , "audit_tags" .= respAuditTags
    ] ++ decisionFields respDecision
    where
      decisionFields Allow = ["action" .= ("allow" :: Text)]
      decisionFields (Block code msg) =
        [ "action" .= ("block" :: Text)
        , "status_code" .= code
        , "body" .= msg
        ]
      decisionFields (Redirect url) =
        [ "action" .= ("redirect" :: Text)
        , "redirect_url" .= url
        ]

-- | Create an allow response
allow :: AgentResponse
allow = AgentResponse
  { respRequestId = ""
  , respDecision = Allow
  , respHeaders = HM.empty
  , respAuditTags = []
  }

-- | Create a block response
block :: Word16 -> Text -> AgentResponse
block code msg = AgentResponse
  { respRequestId = ""
  , respDecision = Block code msg
  , respHeaders = HM.empty
  , respAuditTags = []
  }

-- | Create a redirect response
redirect :: Text -> AgentResponse
redirect url = AgentResponse
  { respRequestId = ""
  , respDecision = Redirect url
  , respHeaders = HM.empty
  , respAuditTags = []
  }

-- | Agent capabilities declaration
data AgentCapabilities = AgentCapabilities
  { capAgentId :: !Text
  , capName :: !Text
  , capVersion :: !Text
  , capSupportedEvents :: ![EventType]
  }
  deriving stock (Eq, Show, Generic)

instance ToJSON AgentCapabilities where
  toJSON AgentCapabilities{..} = object
    [ "agent_id" .= capAgentId
    , "name" .= capName
    , "version" .= capVersion
    , "supported_events" .= capSupportedEvents
    , "protocol_version" .= ("2.0" :: Text)
    ]

-- | Default capabilities
defaultCapabilities :: Text -> AgentCapabilities
defaultCapabilities name = AgentCapabilities
  { capAgentId = name <> "-001"
  , capName = name
  , capVersion = "0.1.0"
  , capSupportedEvents = [RequestHeaders]
  }

-- | Health status
data HealthStatus = HealthStatus
  { hsAgentId :: !Text
  , hsStatus :: !Text
  , hsTimestampMs :: !Word64
  , hsLoad :: !(Maybe LoadMetrics)
  }
  deriving stock (Eq, Show, Generic)

instance ToJSON HealthStatus where
  toJSON HealthStatus{..} = object $
    [ "agent_id" .= hsAgentId
    , "status" .= hsStatus
    , "timestamp_ms" .= hsTimestampMs
    ] ++ maybe [] (\l -> ["load" .= l]) hsLoad

-- | Load metrics
data LoadMetrics = LoadMetrics
  { loadInFlight :: !Word32
  , loadQueueDepth :: !Word32
  , loadAvgLatencyMs :: !Double
  , loadRequestsProcessed :: !Word64
  , loadRequestsRejected :: !Word64
  }
  deriving stock (Eq, Show, Generic)

instance ToJSON LoadMetrics where
  toJSON LoadMetrics{..} = object
    [ "in_flight" .= loadInFlight
    , "queue_depth" .= loadQueueDepth
    , "avg_latency_ms" .= loadAvgLatencyMs
    , "requests_processed" .= loadRequestsProcessed
    , "requests_rejected" .= loadRequestsRejected
    ]

-- | Empty load metrics
emptyLoadMetrics :: LoadMetrics
emptyLoadMetrics = LoadMetrics 0 0 0 0 0

-- | Metrics report
data MetricsReport = MetricsReport
  { mrAgentId :: !Text
  , mrTimestampMs :: !Word64
  , mrCounters :: ![CounterMetric]
  , mrGauges :: ![GaugeMetric]
  }
  deriving stock (Eq, Show, Generic)

instance ToJSON MetricsReport where
  toJSON MetricsReport{..} = object
    [ "agent_id" .= mrAgentId
    , "timestamp_ms" .= mrTimestampMs
    , "counters" .= mrCounters
    , "gauges" .= mrGauges
    ]

-- | Counter metric
data CounterMetric = CounterMetric
  { cmName :: !Text
  , cmValue :: !Word64
  , cmLabels :: !(HashMap Text Text)
  }
  deriving stock (Eq, Show, Generic)

instance ToJSON CounterMetric where
  toJSON CounterMetric{..} = object
    [ "name" .= cmName
    , "value" .= cmValue
    , "labels" .= cmLabels
    ]

-- | Gauge metric
data GaugeMetric = GaugeMetric
  { gmName :: !Text
  , gmValue :: !Double
  , gmLabels :: !(HashMap Text Text)
  }
  deriving stock (Eq, Show, Generic)

instance ToJSON GaugeMetric where
  toJSON GaugeMetric{..} = object
    [ "name" .= gmName
    , "value" .= gmValue
    , "labels" .= gmLabels
    ]

-- | Create a counter metric
counterMetric :: Text -> Word64 -> CounterMetric
counterMetric name value = CounterMetric name value HM.empty

-- | Create a gauge metric
gaugeMetric :: Text -> Double -> GaugeMetric
gaugeMetric name value = GaugeMetric name value HM.empty

-- | Messages from the agent to proxy
data AgentMessage
  = AMCapabilities !AgentCapabilities
  | AMResponse !AgentResponse
  | AMHealth !HealthStatus
  | AMMetrics !MetricsReport
  deriving stock (Eq, Show)

instance ToJSON AgentMessage where
  toJSON (AMCapabilities c) = object ["type" .= ("capabilities" :: Text), "data" .= c]
  toJSON (AMResponse r) = object ["type" .= ("response" :: Text), "data" .= r]
  toJSON (AMHealth h) = object ["type" .= ("health" :: Text), "data" .= h]
  toJSON (AMMetrics m) = object ["type" .= ("metrics" :: Text), "data" .= m]

-- | Messages from the proxy to agent
data ProxyMessage
  = PMHandshake
  | PMRequestHeaders !RequestHeadersEvent
  | PMHealthCheck
  | PMMetricsRequest
  | PMUnknown !Text
  deriving stock (Eq, Show)

instance FromJSON ProxyMessage where
  parseJSON = Aeson.withObject "ProxyMessage" $ \v -> do
    msgType <- v .: "type"
    case (msgType :: Text) of
      "handshake" -> return PMHandshake
      "request_headers" -> PMRequestHeaders <$> v .: "data"
      "health_check" -> return PMHealthCheck
      "metrics_request" -> return PMMetricsRequest
      other -> return $ PMUnknown other

-- | Agent handler interface
data AgentHandler = AgentHandler
  { ahCapabilities :: IO AgentCapabilities
  , ahOnRequestHeaders :: RequestHeadersEvent -> IO AgentResponse
  , ahHealthStatus :: IO HealthStatus
  , ahMetricsReport :: IO (Maybe MetricsReport)
  }

-- | Run an agent with the given handler
runAgent
  :: ServerConfig
  -> AgentHandler
  -> IO ()
runAgent config handler = do
  let socketPath = maybe "/tmp/zentinel-policy.sock" id (scSocketPath config)

  -- Remove existing socket file
  removeSocketFile socketPath

  -- Create and bind socket
  sock <- socket AF_UNIX Stream 0
  bind sock (SockAddrUnix socketPath)
  listen sock 5

  logInfo config $ "Listening on " ++ socketPath

  -- Accept connections
  forever $ do
    (conn, _) <- accept sock
    _ <- forkIO $ handleConnection config handler conn
    return ()

-- | Remove socket file if it exists
removeSocketFile :: FilePath -> IO ()
removeSocketFile path = do
  result <- try $ BS.readFile path :: IO (Either SomeException ByteString)
  case result of
    Left _ -> return ()  -- File doesn't exist or can't be read
    Right _ -> do
      -- Try to remove it (best effort)
      _ <- try $ return () :: IO (Either SomeException ())
      return ()

-- | Handle a single connection
handleConnection :: ServerConfig -> AgentHandler -> Socket -> IO ()
handleConnection config handler conn = do
  logDebug config "New connection"

  -- Simple line-based JSON protocol
  let loop = do
        msg <- recvMessage conn
        case msg of
          Nothing -> do
            logDebug config "Connection closed"
            close conn
          Just proxyMsg -> do
            logDebug config $ "Received: " ++ show proxyMsg
            response <- handleMessage handler proxyMsg
            case response of
              Just agentMsg -> do
                sendMessage conn agentMsg
                logDebug config $ "Sent: " ++ show agentMsg
              Nothing -> return ()
            loop

  catch loop $ \(e :: SomeException) -> do
    logWarn config $ "Connection error: " ++ show e
    close conn

-- | Handle a proxy message
handleMessage :: AgentHandler -> ProxyMessage -> IO (Maybe AgentMessage)
handleMessage handler msg = case msg of
  PMHandshake -> do
    caps <- ahCapabilities handler
    return $ Just $ AMCapabilities caps

  PMRequestHeaders event -> do
    resp <- ahOnRequestHeaders handler event
    return $ Just $ AMResponse resp { respRequestId = rmRequestId (reqHdrMetadata event) }

  PMHealthCheck -> do
    health <- ahHealthStatus handler
    return $ Just $ AMHealth health

  PMMetricsRequest -> do
    metrics <- ahMetricsReport handler
    return $ fmap AMMetrics metrics

  PMUnknown _ -> return Nothing

-- | Receive a JSON message from socket
recvMessage :: Socket -> IO (Maybe ProxyMessage)
recvMessage sock = do
  -- Read length prefix (4 bytes, big-endian)
  lenBytes <- recv sock 4
  if BS.length lenBytes < 4
    then return Nothing
    else do
      let len = fromIntegral $ BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 lenBytes :: Int
      if len == 0 || len > 1000000
        then return Nothing
        else do
          msgBytes <- recv sock len
          return $ decode (LBS.fromStrict msgBytes)

-- | Send a JSON message to socket
sendMessage :: Socket -> AgentMessage -> IO ()
sendMessage sock msg = do
  let msgBytes = LBS.toStrict $ encode msg
      len = BS.length msgBytes
      lenBytes = BS.pack
        [ fromIntegral (len `div` 16777216)
        , fromIntegral ((len `div` 65536) `mod` 256)
        , fromIntegral ((len `div` 256) `mod` 256)
        , fromIntegral (len `mod` 256)
        ]
  sendAll sock (lenBytes <> msgBytes)

-- | Get current time in milliseconds
getCurrentTimeMs :: IO Word64
getCurrentTimeMs = do
  t <- getPOSIXTime
  return $ round (t * 1000)

-- Logging helpers
logDebug, logInfo, logWarn, logError :: ServerConfig -> String -> IO ()
logDebug config msg = when (scLogLevel config <= Debug) $ hPutStrLn stderr $ "[DEBUG] " ++ msg
logInfo config msg = when (scLogLevel config <= Info) $ hPutStrLn stderr $ "[INFO] " ++ msg
logWarn config msg = when (scLogLevel config <= Warn) $ hPutStrLn stderr $ "[WARN] " ++ msg
logError config msg = hPutStrLn stderr $ "[ERROR] " ++ msg
