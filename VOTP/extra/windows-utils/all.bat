@echo off
rem ==========================================================
rem  make-all.bat
rem  Creates/overwrites all.txt and concatenates the requested
rem  files with clear, readable separators.
rem ==========================================================

set "OUT=all.txt"

rem --- Build the file in one shot (>) so it’s always fresh ----------
> "%OUT%" (
    echo -------------[ Cargo.toml ]-------------
    type "Cargo.toml"
    echo(

    echo -------------[ src\util.rs ]-------------
    type "src\util.rs"
    echo(

    echo -------------[ src\key.rs ]-------------
    type "src\key.rs"
    echo(

    echo -------------[ src\main.rs ]-------------
    type "src\main.rs"
    echo(
)

echo Done. Contents written to "%OUT%".
