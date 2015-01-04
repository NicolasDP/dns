{-# LANGUAGE CPP #-}
{-# LANGUAGE RankNTypes #-}
module Network.DNS.WinResolver
    (
#ifdef WINDOWS
      defaultWinResolvConf
#endif
    ) where


#ifdef WINDOWS

import System.Win32.Types (BYTE)
import System.Win32.Registry
import Foreign.Ptr
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.C.String (peekCWString)
import Control.Exception

import Control.Applicative
import Data.Bits
import Data.Either
import Network.DNS.Resolver (ResolvConf(..), FileOrNumericHost(..), defaultResolvConf)
import Network.Socket (HostName)

tryAny :: IO a -> IO (Either SomeException a)
tryAny = try

defaultPath :: FilePath
defaultPath = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"

openValue :: forall a . String -> String -> (Ptr BYTE -> RegValueType -> IO a) -> IO (Either SomeException a)
openValue path key toByteS = tryAny $ bracket openKey regCloseKey $ \hkey -> allocaBytes 4096 $ \mem -> do
    regQueryValueEx hkey key mem 4096 >>= toByteS mem
  where
    openKey = regOpenKeyEx hKEY_LOCAL_MACHINE path kEY_QUERY_VALUE

listValues :: String -> IO (Either SomeException [String])
listValues path = tryAny $ bracket openKey regCloseKey regEnumKeys
  where
    openKey = regOpenKeyEx hKEY_LOCAL_MACHINE path (kEY_ENUMERATE_SUB_KEYS .|. kEY_READ)

fromBlob :: forall a . Ptr a -> RegValueType -> IO String
fromBlob mem ty
    | ty == rEG_SZ = peekCWString (castPtr mem)
    | otherwise = error "wrong type"

defaultWinResolvConf :: IO (Either String ResolvConf)
defaultWinResolvConf = do
    l <- either (error . show) id <$> listValues defaultPath
    lr <- mapM (\k -> openValue (defaultPath ++ "\\" ++ k) "DhcpNameServer" fromBlob) l
    return $ either (Left) (\c -> Right $ defaultResolvConf { resolvInfo = RCHostName c }) $ extractBest $ rights lr

extractBest :: [String] -> Either String HostName
extractBest l
    | null l    = Left "DefaultWinrResolvConf: cannot detect default DHCP Name Server configuration"
    | otherwise = Right $ takeWhile ((/=) ' ') $ head l

#endif
