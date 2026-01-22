-- |
-- Module      : Main
-- Description : CLI entry point for sentinel-policy-agent
-- Copyright   : (c) raskell.io, 2026
-- License     : Apache-2.0

module Main (main) where

import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Environment (lookupEnv)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

import Sentinel.Agent.Policy

main :: IO ()
main = do
  -- Parse CLI options
  opts <- parseCLIOptions

  -- Load configuration
  config <- loadConfiguration opts

  -- Print startup banner
  TIO.putStrLn "╔═══════════════════════════════════════════════════════════╗"
  TIO.putStrLn "║         sentinel-policy-agent v0.1.0                      ║"
  TIO.putStrLn "║         Policy evaluation for Sentinel proxy              ║"
  TIO.putStrLn "╚═══════════════════════════════════════════════════════════╝"
  TIO.putStrLn ""
  TIO.putStrLn $ "Engine:  " <> T.pack (show $ engine config)
  TIO.putStrLn $ "Socket:  " <> T.pack (socketPath config)
  TIO.putStrLn $ "Default: " <> T.pack (show $ defaultDecision config)
  TIO.putStrLn ""

  -- Run the agent
  runPolicyAgent config

-- | Load configuration from file and CLI options
loadConfiguration :: CLIOptions -> IO AgentConfig
loadConfiguration CLIOptions{..} = do
  -- Try loading from config file first
  baseConfig <- case cliConfig of
    Just path -> loadConfig path
    Nothing -> do
      -- Check environment variable
      envConfig <- lookupEnv "POLICY_CONFIG"
      case envConfig of
        Just path -> loadConfig path
        Nothing -> return defaultConfig

  -- Override with CLI options and environment variables
  socketFromEnv <- lookupEnv "AGENT_SOCKET"
  engineFromEnv <- lookupEnv "POLICY_ENGINE"
  logLevelFromEnv <- lookupEnv "LOG_LEVEL"

  return baseConfig
    { socketPath = fromMaybe (socketPath baseConfig) $
        cliSocket `orElse` socketFromEnv
    , engine = fromMaybe (engine baseConfig) $
        cliEngine `orElse` parseEngine engineFromEnv
    , logLevel = fromMaybe (logLevel baseConfig) $
        cliLogLevel `orElse` fmap T.pack logLevelFromEnv
    }

  where
    orElse :: Maybe a -> Maybe a -> Maybe a
    orElse (Just x) _ = Just x
    orElse Nothing y = y

    parseEngine :: Maybe String -> Maybe PolicyEngine
    parseEngine Nothing = Nothing
    parseEngine (Just s) = case s of
      "cedar" -> Just CedarEngine
      "rego"  -> Just RegoEngine
      "opa"   -> Just RegoEngine
      "auto"  -> Just AutoEngine
      _       -> Nothing
