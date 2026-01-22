{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Test.Hspec

import qualified Test.Policy.Cedar as Cedar
import qualified Test.Policy.Rego as Rego
import qualified Test.Policy.Cache as Cache
import qualified Test.Policy.Input as Input

main :: IO ()
main = hspec $ do
  describe "Cedar Engine" Cedar.spec
  describe "Rego Engine" Rego.spec
  describe "Decision Cache" Cache.spec
  describe "Input Mapping" Input.spec
