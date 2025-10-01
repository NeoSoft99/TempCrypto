var rxBareSerpent = new Regex(
    @"(?m)^(?:(?!//).)*?(?<![\w.:])Serpent(?=\s*[);])",
    RegexOptions.CultureInvariant | RegexOptions.Compiled);
