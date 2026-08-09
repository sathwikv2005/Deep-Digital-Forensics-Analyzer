#pragma once

#include <string>
#include <vector>

#include "../models/evidence.h"

class EvidenceSerializer {
   public:
    static bool write(const std::string& path,
                      const std::vector<Evidence>& evidence);
};